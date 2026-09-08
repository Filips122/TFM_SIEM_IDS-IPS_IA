#!/usr/bin/env bash
# Full ARGOS-LAB experiment sweep. Run from src/models/ARGOS_LAB.
# Assumes prepare_dataset.py has already produced both dataset variants.
set -u
log() { echo; echo "### $*"; echo; }

log "1. leakage audit (run this first: it frames every result below)"
python leakage_audit.py --split_mode date
python leakage_audit.py --split_mode random

log "2. supervised binary, three feature regimes, temporal split"
for fs in full nosignature behavioral; do
  python train_ml_binary_hgb.py --split_mode date --feature_set "$fs"
  python train_ml_binary_mlp.py --split_mode date --feature_set "$fs" --epochs 40
done

log "3. supervised binary without posture findings (the manifest's request)"
for fs in full behavioral; do
  python train_ml_binary_hgb.py --split_mode date --dataset ARGOS-LAB-NOPOSTURE --feature_set "$fs"
done

log "4. cross-host generalization: leave-one-agent-out"
python train_ml_binary_hgb.py --split_mode groupkfold --all_folds --feature_set behavioral --no_importance
python train_ml_binary_mlp.py --split_mode groupkfold --all_folds --feature_set behavioral --epochs 30

log "5. multiclass activity family"
python train_ml_multiclass_hgb.py --split_mode date --feature_set behavioral
python train_ml_multiclass_hgb.py --split_mode date --feature_set full --no_importance

log "6. unsupervised anomaly detection"
for policy in quiet benign all; do
  python train_anomaly_isoforest.py --split_mode date --feature_set behavioral --train_policy "$policy"
  python train_anomaly_autoencoder.py --split_mode date --feature_set behavioral --train_policy "$policy" --epochs 60
done

log "7. sequence model"
python prepare_sequence_dataset.py --split_mode date --pipeline binary --feature_set behavioral --seq_len 12
python train_seq_gru.py --split_mode date --pipeline binary --feature_set behavioral --seq_len 12 --epochs 40
python prepare_sequence_dataset.py --split_mode date --pipeline multiclass --feature_set behavioral --seq_len 12
python train_seq_gru.py --split_mode date --pipeline multiclass --feature_set behavioral --seq_len 12 --epochs 40

log "8. comparison table"
python compare_models.py --metric macro_f1
