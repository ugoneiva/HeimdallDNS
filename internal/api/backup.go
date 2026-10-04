// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ugoneiva/HeimdallDNS/internal/backup"
)

const maxRestoreSize = 4 << 30

func (a *api) backupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/backup", a.downloadBackup)
	mux.HandleFunc("GET /api/backups", a.listBackups)
	mux.HandleFunc("POST /api/backups", a.runBackup)
	mux.HandleFunc("GET /api/backups/{name}", a.getBackup)
	mux.HandleFunc("GET /api/restore", a.restoreState)
	mux.HandleFunc("POST /api/restore", a.restore)
	mux.HandleFunc("DELETE /api/restore", a.cancelRestore)
	mux.HandleFunc("POST /api/restart", a.restart)
}

func (a *api) backupOptions(full bool, pass string) backup.Options {
	return backup.Options{Store: a.Store, TempDir: a.DataDir, ConfigPath: a.ConfigPath, Full: full, Passphrase: pass, Version: a.Version}
}

// downloadBackup gera um backup na hora e entrega para download. A senha vem
// no corpo (nunca na URL).
func (a *api) downloadBackup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Full       bool   `json:"full"`
		Passphrase string `json:"passphrase"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Passphrase != "" && len(body.Passphrase) < 10 {
		writeErr(w, http.StatusBadRequest, errors.New("use uma senha de backup com 10 caracteres ou mais"))
		return
	}
	f, err := os.CreateTemp(a.DataDir, ".download-*.tar.gz")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer os.Remove(f.Name())
	defer f.Close()
	m, err := backup.Write(f, a.backupOptions(body.Full, body.Passphrase))
	a.audit(r, "backup.download", "", map[string]any{"full": body.Full, "encrypted": body.Passphrase != ""}, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	name := fmt.Sprintf("heimdalldns-%s-%s.tar.gz", safeName(m.Hostname), m.Created.Local().Format("20060102-1504"))
	if m.Encrypted {
		name += ".age"
	}
	fi, _ := f.Stat()
	_, _ = f.Seek(0, io.SeekStart)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprint(fi.Size()))
	_, _ = io.Copy(w, f)
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "servidor"
	}
	return s
}

func (a *api) listBackups(w http.ResponseWriter, _ *http.Request) {
	files, err := backup.List(a.BackupDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": files, "dir": a.BackupDir, "auto": a.BackupAuto})
}

func (a *api) runBackup(w http.ResponseWriter, r *http.Request) {
	name, err := backup.Auto{Options: a.backupOptions(false, ""), Dir: a.BackupDir, Keep: max(1, a.BackupKeep)}.RunOnce()
	a.audit(r, "backup.create", filepath.Base(name), nil, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.listBackups(w, r)
}

func (a *api) getBackup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !backup.ValidName(name) {
		writeErr(w, http.StatusBadRequest, errors.New("nome inválido"))
		return
	}
	f, err := os.Open(filepath.Join(a.BackupDir, name))
	if err != nil {
		writeErr(w, http.StatusNotFound, errors.New("cópia não encontrada"))
		return
	}
	defer f.Close()
	a.audit(r, "backup.download", name, nil, nil)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(w, r, name, time.Time{}, f)
}

func (a *api) restoreState(w http.ResponseWriter, _ *http.Request) {
	m, err := backup.Staged(a.DataDir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": m, "can_restart": a.Restart != nil})
}

// restore recebe o arquivo (multipart: "passphrase" antes de "file"),
// confere e deixa pronto para a próxima partida.
func (a *api) restore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRestoreSize)
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("envie o arquivo como multipart/form-data"))
		return
	}
	var pass string
	var arc *backup.Archive
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		switch p.FormName() {
		case "passphrase":
			b, _ := io.ReadAll(io.LimitReader(p, 1024))
			pass = string(b)
		case "file":
			if arc, err = backup.Open(p, pass, a.DataDir); err != nil {
				a.audit(r, "backup.restore", p.FileName(), nil, err)
				code := http.StatusBadRequest
				if errors.Is(err, backup.ErrPassphrase) {
					code = http.StatusUnauthorized
				}
				writeErr(w, code, err)
				return
			}
		}
		p.Close()
	}
	if arc == nil {
		writeErr(w, http.StatusBadRequest, errors.New("nenhum arquivo enviado"))
		return
	}
	defer arc.Close()
	err = arc.Stage(a.DataDir)
	a.audit(r, "backup.restore", arc.Manifest.Hostname, map[string]any{
		"created": arc.Manifest.Created, "version": arc.Manifest.Version, "full": arc.Manifest.Full,
	}, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": arc.Manifest, "can_restart": a.Restart != nil,
		"config_included": arc.Manifest.HasConfig})
}

func (a *api) cancelRestore(w http.ResponseWriter, r *http.Request) {
	err := backup.CancelStaged(a.DataDir)
	a.audit(r, "backup.restore_cancel", "", nil, err)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// restart reinicia o serviço (o mesmo processo, com exec) para aplicar uma
// restauração.
func (a *api) restart(w http.ResponseWriter, r *http.Request) {
	if a.Restart == nil {
		writeErr(w, http.StatusNotImplemented, errors.New("reinicie o serviço manualmente (systemctl restart heimdalldns)"))
		return
	}
	a.audit(r, "service.restart", "", nil, nil)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "reiniciando"})
	go func() {
		time.Sleep(300 * time.Millisecond) // deixa a resposta sair
		a.Restart()
	}()
}
