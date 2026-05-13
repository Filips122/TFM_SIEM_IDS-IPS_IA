Ahora tienes dos formas nuevas:
Ventana desde un tiempo concreto:
    python .\src\models\CSR-LANL\prepare_dataset.py --split_mode random --source_set auth_flow_dns --time_min 145000 --time_window_hours 6 --progress_every_chunks 10 --progress_every_rows 500000

Esto procesa solo 6 horas desde 145000, es decir hasta 166600.



Ventana alrededor de eventos red-team:
    python .\src\models\CSR-LANL\prepare_dataset.py --split_mode random --source_set auth_flow_dns --redteam_window_hours 2 --redteam_window_limit 1 --progress_every_chunks 10 --progress_every_rows 500000



Esto procesa +/- 2 horas alrededor del primer evento red-team, o sea unas 4 horas totales. Para los primeros 5 eventos red-team:
    python .\src\models\CSR-LANL\prepare_dataset.py --split_mode random --source_set auth_flow_dns --redteam_window_hours 2 --redteam_window_limit 5

También queda guardado en metadata qué intervalos efectivos se usaron (effective_time_intervals), para que luego sea reproducible.