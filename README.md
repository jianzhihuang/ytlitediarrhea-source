# YTLiteDiarrhea SideStore Source

Auto-updating SideStore source for [diarrhea3/YTLiteDiarrhea](https://github.com/diarrhea3/YTLiteDiarrhea).

## Source URL

Use this in SideStore after the first workflow run succeeds:

`https://raw.githubusercontent.com/jianzhihuang/ytlitediarrhea-sidestore-source/main/apps.json`

## What It Does

- Polls the upstream GitHub releases every 6 hours
- Downloads the latest stable IPA asset
- Extracts app metadata from the IPA
- Updates `apps.json`
- Commits the change automatically

The workflow skips releases whose name matches `crashes on launch`.
