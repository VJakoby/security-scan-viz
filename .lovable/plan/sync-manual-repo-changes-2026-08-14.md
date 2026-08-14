# Sync Manual Repo Changes

## Current state (verified)
- Local branch `edit/edt-e14e0fb9-5167-4475-b594-4c7791ba25ae` and `origin/main` both point to commit `4abcd37`.
- `git status` is clean: no staged, unstaged, or untracked changes.
- Conclusion: the remote `main` branch is already synced into this workspace.
- Build check surfaced three TypeScript errors that appear to be part of the current synced code:
  - `src/hooks/useHtmlExport.ts(6,6)`: `replaceAll` not available with current `lib` target.
  - `src/lib/scannerParsers.ts(305,3)` and surrounding lines: type mismatch when assigning XML element collections, and missing DOM properties on `ParentNode`/`unknown`.

## What this plan will do
1. Read the most recently changed files to summarize what the manual update introduced.
2. Fix the TypeScript build errors so the project compiles cleanly.
3. Report the summary and fixes back to you.
4. If any of those changes need refinements or follow-up features, create a separate build plan for the next steps.

## Files to inspect and fix
- `src/hooks/useHtmlExport.ts` — replace `replaceAll` with a compatible alternative or update `tsconfig.app.json` `lib`.
- `src/lib/scannerParsers.ts` — add proper type casts/casts for XML parsing results.
- `tsconfig.app.json` — evaluate bumping the `lib` array to include ES2021 if needed.
- `src/hooks/useNmapParser.ts`
- `src/components/vulnerability/*`
- `src/hooks/useVulnerabilityData.ts`
- `src/types/vulnerability.ts`

## Expected outcome
The project builds without TypeScript errors, and you get a concise summary of what changed in the latest commit so you can confirm it matches your manual update.