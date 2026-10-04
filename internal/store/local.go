package store

// LocalRecord é um registro DNS local criado pelo painel ou importado.
type LocalRecord struct {
	Name  string `json:"name"`  // nas.casa
	Type  string `json:"type"`  // A, AAAA ou CNAME
	Value string `json:"value"` // IP ou nome de destino
}

// UpstreamSettings sobrepõe os upstreams do arquivo de configuração.
type UpstreamSettings struct {
	Servers []string `json:"servers"`
	Mode    string   `json:"mode"`
}
