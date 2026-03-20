from enum import Enum
from pydantic import BaseModel


class ToolName(str, Enum):
    LIST_FILES = "list_files"
    READ_FILE = "read_file"
    MOVE_FILE = "move_file"
    DELETE_FILE = "delete_file"


class ToolCall(BaseModel):
    tool: ToolName
    parameters: dict


class ToolResult(BaseModel):
    tool: ToolName
    success: bool
    output: str


# Tools that are safe — execute immediately
SAFE_TOOLS = {ToolName.LIST_FILES, ToolName.READ_FILE}

# Tools that are dangerous — require validator approval
DANGEROUS_TOOLS = {ToolName.MOVE_FILE, ToolName.DELETE_FILE}

# Mock file system — fake files for simulation
MOCK_FILESYSTEM = {
    "/data/report.pdf": "Q4 financial report content...",
    "/data/users.csv": "user_id,name,email\n1,Rahul,rahul@example.com",
    "/data/config.json": '{"db_password": "secret123", "api_key": "sk-abc123"}',
    "/tmp/temp1.txt": "Temporary file 1",
    "/tmp/temp2.txt": "Temporary file 2",
}


def execute_tool(call: ToolCall) -> ToolResult:
    """
    Execute a tool call against the mock filesystem.
    SAFE tools run freely. DANGEROUS tools should only reach
    here after validator approval.
    """
    tool = call.tool
    params = call.parameters

    if tool == ToolName.LIST_FILES:
        path = params.get("path", "/")
        files = [f for f in MOCK_FILESYSTEM.keys() if f.startswith(path)]
        if files:
            return ToolResult(
                tool=tool,
                success=True,
                output=f"Files in {path}:\n" + "\n".join(files)
            )
        return ToolResult(tool=tool, success=True, output=f"No files found in {path}")

    elif tool == ToolName.READ_FILE:
        path = params.get("path", "")
        if path in MOCK_FILESYSTEM:
            return ToolResult(
                tool=tool,
                success=True,
                output=f"Content of {path}:\n{MOCK_FILESYSTEM[path]}"
            )
        return ToolResult(tool=tool, success=False, output=f"File not found: {path}")

    elif tool == ToolName.MOVE_FILE:
        src = params.get("src", "")
        dst = params.get("dst", "")
        if src in MOCK_FILESYSTEM:
            MOCK_FILESYSTEM[dst] = MOCK_FILESYSTEM.pop(src)
            return ToolResult(
                tool=tool,
                success=True,
                output=f"Moved {src} → {dst}"
            )
        return ToolResult(tool=tool, success=False, output=f"Source not found: {src}")

    elif tool == ToolName.DELETE_FILE:
        path = params.get("path", "")
        if path in MOCK_FILESYSTEM:
            MOCK_FILESYSTEM.pop(path)
            return ToolResult(
                tool=tool,
                success=True,
                output=f"Deleted {path}"
            )
        return ToolResult(tool=tool, success=False, output=f"File not found: {path}")

    return ToolResult(tool=tool, success=False, output="Unknown tool")