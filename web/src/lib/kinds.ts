// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { CircleHelp, Cctv, Cpu, Gamepad2, Laptop, Printer, Router, Server, Smartphone, Speaker, Tablet, Tv } from 'lucide-react'
import type { ComponentType } from 'react'
import { t } from './i18n'

type Icon = ComponentType<{ className?: string; 'aria-hidden'?: boolean }>

/** Ícone e nome de cada tipo de aparelho (o servidor deduz o tipo). */
export const kindIcon: Record<string, Icon> = {
  phone: Smartphone, tablet: Tablet, computer: Laptop, tv: Tv, printer: Printer, camera: Cctv, console: Gamepad2,
  speaker: Speaker, server: Server, router: Router, iot: Cpu, unknown: CircleHelp,
}
export const kindLabel: Record<string, string> = {
  phone: t('Celular'), tablet: t('Tablet'), computer: t('Computador'), tv: t('TV'), printer: t('Impressora'),
  camera: t('Câmera'), console: t('Videogame'), speaker: t('Caixa de som'), server: t('Servidor'), router: t('Roteador'),
  iot: t('Casa inteligente (IoT)'), unknown: t('Desconhecido'),
}
