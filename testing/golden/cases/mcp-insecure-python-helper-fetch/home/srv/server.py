"""Web search and fetch server (duckduckgo-mcp-server 0.7 shape, reduced)."""
import httpx
from bs4 import BeautifulSoup
from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("ddg-search")


class DuckDuckGoSearcher:
    BASE_URL = "https://html.duckduckgo.com/html"

    async def search(self, query: str, ctx: Context, max_results: int = 10):
        html = await self._request({"q": query})
        soup = BeautifulSoup(html, "html.parser")
        results = []
        for result in soup.select(".result"):
            results.append(result.get_text())
        return results[:max_results]

    async def _request(self, data: dict) -> str:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.BASE_URL, data=data, timeout=30.0
            )
            response.raise_for_status()
            return response.text


class WebContentFetcher:
    async def _fetch_httpx(self, url: str) -> str:
        current = url
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(
                current, timeout=30.0
            )
            response.raise_for_status()
            return response.text

    async def fetch_and_parse(self, url: str, ctx: Context, max_length: int = 8000) -> str:
        html = await self._fetch_httpx(url)
        text = BeautifulSoup(html, "html.parser").get_text()
        return text[:max_length]


searcher = DuckDuckGoSearcher()
fetcher = WebContentFetcher()


@mcp.tool()
async def search(query: str, ctx: Context, max_results: int = 10) -> str:
    results = await searcher.search(query, ctx, max_results)
    return "\n".join(results)


@mcp.tool()
async def fetch_content(url: str, ctx: Context) -> str:
    return await fetcher.fetch_and_parse(url, ctx)
