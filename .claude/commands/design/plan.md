---
description: Create a one-page Design Brief for the specified surface, then a build-plan.
argument-hint: <surface or goal>
---
Use the frontend-designer subagent to:
1) Draft `docs/design/brief.md` scoped to "$ARGUMENTS".
2) Produce `docs/design/implementation/$ARGUMENTS.md` with components to use (shadcn), routes, and a PR checklist.
