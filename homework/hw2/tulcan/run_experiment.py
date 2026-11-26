"""Execute the full local notebook with the current Python interpreter.

Requires the dedicated hw2-tulcan Docker lab, Semgrep image, and local Ollama.
Set DOCKER_EXE when Docker is not on PATH. No other containers are modified.
"""
import ast
import json
import os
import shutil
import sys
from pathlib import Path

import nbformat
from jupyter_client import KernelManager
from nbclient import NotebookClient

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
os.chdir(HERE)
sys.path.insert(0, str(HERE))
from experiment_support import docker


def main():
    os.environ.setdefault('DVWA_BASE', 'http://127.0.0.1:4280')
    os.environ.setdefault('DVWA_USERNAME', 'admin')
    os.environ.setdefault('DVWA_PASSWORD', 'password')  # Public DVWA lab default only.
    path = HERE / 'hw2_web_attack_defend.ipynb'
    notebook = nbformat.read(path, as_version=4)
    # Load only the stdlib client, without executing notebook experiments.
    namespace = {}
    imports = '''import re, urllib.request, urllib.parse
from http.cookiejar import CookieJar
'''
    exec(imports, namespace)
    for cell in notebook.cells:
        if cell.cell_type == 'code':
            tree = ast.parse(cell.source)
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == 'DVWAClient':
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<client>', 'exec'), namespace)
    client = namespace['DVWAClient'](os.environ['DVWA_BASE'])
    # Only initialize the isolated lab DB on a fresh, uninitialized installation.
    page = client.get('setup.php')
    if os.environ.get('HW2_INITIALIZE_DB') == '1':
        result = client.post_form('setup.php', {'create_db':'Create / Reset Database',
                                              'user_token':client.token(page)})
        if 'Setup successful' not in result and 'created' not in result:
            raise RuntimeError('DVWA setup did not report database creation.')
    client.login(os.environ['DVWA_USERNAME'], os.environ['DVWA_PASSWORD'])
    client.set_security('medium')
    container = os.environ.get('DVWA_CONTAINER', 'hw2-tulcan-dvwa-1')
    source_map = {'sqli_medium.php': 'sqli', 'xss_medium.php': 'xss_r', 'exec_medium.php': 'exec'}
    for filename, endpoint in source_map.items():
        live = docker('exec', container, 'cat', f'/var/www/html/vulnerabilities/{endpoint}/source/medium.php')
        saved = (HERE / 'duel' / 'dvwa_source' / filename).read_text(encoding='utf-8')
        if live.strip() != saved.strip():
            raise RuntimeError(f'{filename}: scan snapshot differs from running target; review before scanning.')
    archive = HERE / 'duel' / 'original'
    archive.mkdir(exist_ok=True)
    for name in ['part_c_results.json', 'part_c_metrics.csv']:
        if not (archive / name).exists():
            shutil.copy2(HERE / 'duel' / name, archive / name)
    versions = {
        'python': sys.version,
        'docker': docker('version', '--format', '{{.Server.Version}}'),
        'images': json.loads(docker('image', 'inspect',
            docker('inspect', '--format', '{{.Image}}', container),
            docker('inspect', '--format', '{{.Image}}', 'hw2-tulcan-db-1'))),
        'dvwa_source_commit': os.environ.get('DVWA_SOURCE_COMMIT', 'see image RepoDigests'),
    }
    (HERE / 'duel' / 'environment.json').write_text(json.dumps(versions, indent=2), encoding='utf-8')
    if '--part-c' in sys.argv or '--scanner-only' in sys.argv:
        versions['tool_images'] = json.loads(docker('image', 'inspect', 'semgrep/semgrep', 'alpine/ollama'))
        versions['ollama_version'] = docker('exec', 'hw2-tulcan-ollama', 'ollama', '--version')
        (HERE / 'duel' / 'environment.json').write_text(json.dumps(versions, indent=2), encoding='utf-8')
    kernel = KernelManager(kernel_name='python3')
    kernel.kernel_spec.argv[0] = sys.executable
    full_cells = list(notebook.cells)
    selected = list(range(len(full_cells)))
    if '--part-ab' in sys.argv:
        selected = list(range(26))
    elif '--part-c' in sys.argv:
        selected = [2, *range(26, len(full_cells))]
    elif '--deployed-only' in sys.argv:
        selected = [2, 3, 5, 7, 9, 10, 12, 23]
    elif '--scanner-only' in sys.argv:
        selected = [2, 26, 27, 28, 29]
    notebook.cells = [full_cells[index] for index in selected]
    executor = NotebookClient(notebook, km=kernel, timeout=1200,
                              resources={'metadata': {'path': str(HERE)}})
    executor.on_cell_start = lambda cell, cell_index, **kw: print(f'Cell {cell_index}: {cell.cell_type}', flush=True)
    try:
        executor.execute()
    finally:
        # Preserve outputs from other completed stages when running a subset.
        full_cells = list(nbformat.read(path, as_version=4).cells)
        for original_index, executed in zip(selected, notebook.cells):
            full_cells[original_index] = executed
        notebook.cells = full_cells
        nbformat.write(notebook, path)
        if kernel.has_kernel:
            kernel.shutdown_kernel(now=True)
    print('Full notebook execution completed.', flush=True)


if __name__ == '__main__':
    main()
