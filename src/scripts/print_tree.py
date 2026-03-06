from pathlib import Path
import sys

EXCLUDE_DIRS = {".venv"}

def tree_lines(root: Path):
    """Devuelve una lista de líneas con el árbol del directorio."""
    root = root.resolve()
    lines = [str(root)]

    def _walk(dirpath: Path, prefix: str = ""):
        items = []
        for p in dirpath.iterdir():
            if p.is_dir() and p.name in EXCLUDE_DIRS:
                continue
            items.append(p)

        # Directorios primero, luego archivos
        items.sort(key=lambda p: (p.is_file(), p.name.lower()))

        for i, p in enumerate(items):
            last = (i == len(items) - 1)
            connector = "└── " if last else "├── "
            lines.append(prefix + connector + p.name)

            if p.is_dir():
                extension = "    " if last else "│   "
                _walk(p, prefix + extension)

    _walk(root)
    return lines

def save_tree(root: Path, out_file: Path):
    lines = tree_lines(root)
    out_file = out_file.resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(r"Uso: python print_tree.py C:\\Users\\xfeli\\Desktop\\TFM\\modelos [salida.txt]")
        sys.exit(1)

    root = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("tree.txt")

    out_path = save_tree(root, out)
    print(f"Árbol guardado en: {out_path}")