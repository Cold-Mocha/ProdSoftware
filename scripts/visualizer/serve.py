from __future__ import annotations

import gzip
import http.server
import json
import os
import threading
import urllib.parse
from pathlib import Path
from socketserver import ThreadingMixIn

from aggregator import (
    RAIZ,
    RUTA_REPOS,
    calcular_mtime_fuentes,
    construir_dataset,
)

PUERTO = int(os.environ.get("PORT", 4173))
DIRECTORIO_SERVIR = Path(__file__).resolve().parent


class ServidorEnHilos(ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class CacheAgregado:
    def __init__(self):
        self._lock = threading.Lock()
        self._cuerpo: bytes | None = None
        self._etag: str = ""
        self._mtime_max: float = -1.0

    def obtener(self) -> tuple[bytes, str]:
        mtime_actual = calcular_mtime_fuentes()
        with self._lock:
            if self._cuerpo is not None and mtime_actual == self._mtime_max:
                return self._cuerpo, self._etag

            dataset = construir_dataset()
            cuerpo = json.dumps(dataset, ensure_ascii=False, default=str).encode("utf-8")
            etag = f'"{int(mtime_actual * 1000)}-{len(cuerpo)}"'

            self._cuerpo = cuerpo
            self._etag = etag
            self._mtime_max = mtime_actual
            return cuerpo, etag


CACHE = CacheAgregado()


class Manejador(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DIRECTORIO_SERVIR), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        ruta = parsed.path.split("?")[0]

        if ruta in ("/data/secpipeline.json", "/secpipeline.json"):
            self._servir_dataset()
            return

        if ruta.startswith("/data/repos/"):
            self._servir_archivo_repo(ruta[len("/data/repos/"):])
            return

        super().do_GET()

    def _servir_dataset(self) -> None:
        try:
            cuerpo, etag = CACHE.obtener()
        except Exception as error:
            self.send_error(500, f"Error agregando dataset: {error}")
            return

        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            return

        accept_enc = self.headers.get("Accept-Encoding", "")
        usar_gzip = "gzip" in accept_enc
        cuerpo_final = gzip.compress(cuerpo, compresslevel=1) if usar_gzip else cuerpo

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo_final)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("ETag", etag)
        self.send_header("Access-Control-Allow-Origin", "*")
        if usar_gzip:
            self.send_header("Content-Encoding", "gzip")
        self.end_headers()
        self.wfile.write(cuerpo_final)

    def _servir_archivo_repo(self, rel: str) -> None:
        rel_limpia = urllib.parse.unquote(rel)
        ruta_solicitada = (RUTA_REPOS / rel_limpia).resolve()
        try:
            ruta_solicitada.relative_to(RUTA_REPOS.resolve())
        except ValueError:
            self.send_error(403, "Ruta fuera del directorio de repositorios")
            return

        if not ruta_solicitada.exists() or not ruta_solicitada.is_file():
            self.send_error(404, f"Archivo no encontrado: {rel_limpia}")
            return

        try:
            datos = ruta_solicitada.read_bytes()
        except OSError as error:
            self.send_error(500, f"Error leyendo archivo: {error}")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(datos)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(datos)

    def log_message(self, fmt: str, *args: object) -> None:
        if args and ("/data/secpipeline.json" in str(args[0]) or "/data/repos/" in str(args[0])):
            return
        super().log_message(fmt, *args)


def main() -> int:
    os.chdir(DIRECTORIO_SERVIR)
    print(f"Dashboard      -> http://localhost:{PUERTO}")
    print(f"Dataset (live) -> http://localhost:{PUERTO}/data/secpipeline.json")
    print(f"Raiz proyecto  -> {RAIZ}")
    ServidorEnHilos(("0.0.0.0", PUERTO), Manejador).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
