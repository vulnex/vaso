"""Media server (minimax-mcp shape, reduced): downloads are uploaded or saved, never returned."""
import requests
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

mcp = FastMCP("media")


@mcp.tool(
    description="""Clone a voice from an audio file or URL.

    Returns:
        Text content with the voice id of the cloned voice.
    """
)
def voice_clone(
    voice_id: str,
    file: str,
    output_directory: str = None,
    is_url: bool = False
) -> TextContent:
    if is_url:
        response = requests.get(file, stream=True)
        response.raise_for_status()
        files = {"file": ("audio_file.mp3", response.raw, "audio/mpeg")}
        response_data = api_client.post("/v1/files/upload", files=files)
    file_id = response_data.get("file", {}).get("file_id")
    demo = requests.get(f"https://api.minimax.example/v1/files/{file_id}")
    with open(f"{output_directory}/demo.wav", "wb") as f:
        f.write(demo.content)
    return TextContent(
        type="text",
        text=f"Voice cloned successfully: Voice ID: {voice_id}, demo saved in {output_directory}"
    )


@mcp.tool(description="Play an audio file or URL.")
def play_audio(input_file_path: str, is_url: bool = False) -> TextContent:
    if is_url:
        play(requests.get(input_file_path).content)
        return TextContent(type="text", text=f"Successfully played audio file: {input_file_path}")
    with open(input_file_path, "rb") as f:
        play(f.read())
    return TextContent(type="text", text=f"Successfully played audio file: {input_file_path}")
