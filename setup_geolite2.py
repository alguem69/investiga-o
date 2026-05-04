import os
import tarfile
from pathlib import Path

import requests


def download_geolite2_db() -> Path:
    """
    Baixa o GeoLite2-City.mmdb usando a licenca gratuita da MaxMind.
    Requer a variavel de ambiente MAXMIND_LICENSE_KEY.
    """
    license_key = os.getenv("MAXMIND_LICENSE_KEY", "").strip()
    if not license_key:
        raise RuntimeError("Defina MAXMIND_LICENSE_KEY para baixar o GeoLite2.")

    target_dir = Path(".")
    archive_path = target_dir / "GeoLite2-City.tar.gz"
    db_path = target_dir / "GeoLite2-City.mmdb"

    url = (
        "https://download.maxmind.com/app/geoip_download"
        "?edition_id=GeoLite2-City&license_key="
        f"{license_key}&suffix=tar.gz"
    )
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    archive_path.write_bytes(response.content)

    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.name.endswith("GeoLite2-City.mmdb"):
                member_file = archive.extractfile(member)
                if member_file is None:
                    continue
                db_path.write_bytes(member_file.read())
                break

    if not db_path.exists():
        raise RuntimeError("Nao foi possivel extrair GeoLite2-City.mmdb do arquivo baixado.")

    archive_path.unlink(missing_ok=True)
    return db_path


if __name__ == "__main__":
    output = download_geolite2_db()
    print(f"GeoLite2 instalado em: {output.resolve()}")
    print("Opcional: exporte GEOLITE2_DB_PATH para um caminho customizado.")
