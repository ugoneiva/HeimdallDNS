// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 JLW Security

import { Emblem } from './art'

/** Marca do HeimdallDNS: o escudo do guardião com a Bifröst, o olho e a runa Algiz. */
export function Logo({ className }: { className?: string }) {
  return <Emblem className={className} />
}
