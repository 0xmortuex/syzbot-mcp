"""The real server over stdio: tool list, and that instructive error text
reaches the client (MCPServer hides anything that isn't a ToolError)."""

import os
import sys

import pytest

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

EXPECTED = {"syzbot_bugs", "syzbot_bug", "syzbot_report", "syzbot_repro", "syzbot_explain"}
REPORT = os.path.join(os.path.dirname(__file__), "fixtures", "reports", "report_kcsan.txt")


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_tools_and_errors_over_stdio():
    params = StdioServerParameters(command=sys.executable, args=["-m", "syzbot_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "syzbot"
        names = {t.name for t in (await session.list_tools()).tools}
        assert names == EXPECTED

        # Offline: no network needed for either call.
        bad = await session.call_tool("syzbot_bug", {"bug": "not-a-bug"})
        assert bad.is_error and "extid (20 hex chars" in bad.content[0].text

        empty = await session.call_tool("syzbot_explain", {"text": "   "})
        assert empty.is_error and "paste the crash report" in empty.content[0].text

        with open(REPORT, encoding="utf-8") as fh:
            ok = await session.call_tool("syzbot_explain", {"text": fh.read()})
        assert not ok.is_error and "KCSAN data-race" in ok.content[0].text
