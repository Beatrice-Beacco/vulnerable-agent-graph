# Benchmark content derived from TAMAS

The benchmark **cases** (`cases/`) and **tool catalog** (`catalog.json`) in this
directory are derived from the TAMAS benchmark
(https://github.com/microsoft/TAMAS), by Kavathekar, Jain, Rathod, Kumaraguru
and Ganu (arXiv:2511.05269):

- the cases (agent names, descriptions, user queries) are the benchmark data,
  Community Data License Agreement – Permissive – 2.0 (see LICENSE.CDLA-2.0);
- the catalog (tool names, parameters, return strings, benign/attack origin,
  and the security labels assigned to each tool) is distilled from the
  MIT-licensed tool code (see LICENSE.MIT).

These two files are now maintained as the project's own data. The project does
not import, execute or read any TAMAS source code or repository: the tools are
generated from the catalog (`tamas/tools.py`) and the cases are read as data
(`tamas/load.py`).
