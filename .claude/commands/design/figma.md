---
description: Query and work with Figma designs for LegitPoker.
argument-hint: <action> [node-id]
---
Use the frontend-designer subagent to interact with Figma designs.

**Available actions:**
- `inspect [node-id]` - Get detailed code and metadata for a Figma node (current selection if no node-id)
- `screenshot [node-id]` - Capture a screenshot of a Figma node
- `variables [node-id]` - Extract design variables (colors, spacing, typography) from a node
- `metadata [page-id]` - Get structural overview of a page or node
- `code-connect [node-id]` - Get code component mappings for a node

**Arguments:** $ARGUMENTS

The subagent will:
1. Use the appropriate Figma MCP tool based on the action
2. Parse and present the information in a structured format
3. For `inspect`, provide:
   - Generated code (React/Tailwind)
   - Design tokens used
   - Component structure
4. For `variables`, extract and format:
   - Color palette
   - Typography scale
   - Spacing/sizing system
   - Any other design tokens
5. Suggest actionable next steps for implementing the design in code
