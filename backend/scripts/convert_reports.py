import argparse
from importlib import import_module
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Convert local security-report PDFs to Markdown with Microsoft MarkItDown."
    )
    parser.add_argument(
        "source",
        type=Path,
        help="Directory containing source PDF reports.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory; defaults to <source>/../Markdown Conversions.",
    )
    args = parser.parse_args()

    source_dir = args.source.resolve()
    output_dir = (args.output or source_dir.parent / "Markdown Conversions").resolve()
    if not source_dir.is_dir():
        raise SystemExit(f"Source directory does not exist: {source_dir}")

    try:
        MarkItDown = import_module("markitdown").MarkItDown
    except ImportError as exc:
        raise SystemExit(
            "MarkItDown is optional. Install backend/requirements-integrations.txt first."
        ) from exc

    converter = MarkItDown(enable_plugins=False)
    pdf_files = sorted(source_dir.rglob("*.pdf"))
    output_dir.mkdir(parents=True, exist_ok=True)

    for index, pdf_path in enumerate(pdf_files, start=1):
        relative_path = pdf_path.relative_to(source_dir)
        markdown_path = (output_dir / relative_path).with_suffix(".md")
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        result = converter.convert_local(str(pdf_path))
        markdown_path.write_text(result.text_content, encoding="utf-8")
        print(f"[{index}/{len(pdf_files)}] {relative_path} -> {markdown_path}")

    print(f"Converted {len(pdf_files)} PDF report(s) into {output_dir}")


if __name__ == "__main__":
    main()
