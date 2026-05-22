import requests
import json

ORG = "sveltejs"
BASE_PATH = "data/repos"
TOP_N = 10


def get_top_repos_por_estrellas():
    cabeceras = {"Accept": "application/vnd.github.v3+json"}
    todos_los_repos = []
    pagina = 1

    while True:
        url = f"https://api.github.com/orgs/{ORG}/repos?per_page=100&page={pagina}"
        respuesta = requests.get(url, headers=cabeceras)

        if respuesta.status_code != 200:
            print(f"Error al conectar con la API: {respuesta.status_code}")
            break

        repos = respuesta.json()
        if not repos:
            break

        todos_los_repos.extend(repos)
        pagina += 1

    repos_ordenados = sorted(
        todos_los_repos,
        key=lambda r: r.get("stargazers_count", 0),
        reverse=True,
    )

    return [
        {
            "url": repo["clone_url"],
            "path": f"{BASE_PATH}/{repo['name']}",
            "ref": repo.get("default_branch", "main"),
        }
        for repo in repos_ordenados[:TOP_N]
    ]


top_repos = get_top_repos_por_estrellas()
data = {"repositories": top_repos}

with open("data/repos.json", "w") as f:
    json.dump(data, f, indent=4)

print(f"Se encontraron {len(top_repos)} repositorios con mas estrellas.")
print("Archivo 'data/repos.json' generado exitosamente.")
