#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep-learning architectures for ARGOS-LAB window data."""

from __future__ import annotations

import torch
import torch.nn as nn


class MLP(nn.Module):
    """Dense classifier over a single window's feature vector.

    BatchNorm is used instead of the plain Linear/ReLU/Dropout stack of the
    sibling datasets: ARGOS-LAB features span very different magnitudes
    (alert_count reaches 5,470 while entropies live in [0, 1]) and the extra
    normalisation keeps training stable under heavy class weighting.
    """

    def __init__(self, in_features: int, n_classes: int, hidden: int = 256, depth: int = 3, dropout: float = 0.3):
        super().__init__()
        layers: list[nn.Module] = []
        dim = in_features
        for _ in range(depth):
            layers += [nn.Linear(dim, hidden), nn.BatchNorm1d(hidden), nn.ReLU(), nn.Dropout(dropout)]
            dim = hidden
        layers += [nn.Linear(dim, n_classes)]
        self.net = nn.Sequential(*layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class TabularAutoencoder(nn.Module):
    """Symmetric autoencoder used for unsupervised anomaly scoring.

    Trained only to reconstruct routine traffic; the per-window reconstruction
    error becomes the anomaly score. No label is ever seen during fitting.
    """

    def __init__(self, in_features: int, latent: int = 12, hidden: int = 96, dropout: float = 0.1):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(in_features, hidden), nn.BatchNorm1d(hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden // 2), nn.BatchNorm1d(hidden // 2), nn.ReLU(),
            nn.Linear(hidden // 2, latent),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent, hidden // 2), nn.BatchNorm1d(hidden // 2), nn.ReLU(),
            nn.Linear(hidden // 2, hidden), nn.BatchNorm1d(hidden), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden, in_features),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))

    @torch.no_grad()
    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        return ((self(x) - x) ** 2).mean(dim=1)


class GRUSequenceClassifier(nn.Module):
    """Classifies the last window of a per-agent sequence.

    The point of the recurrent model is that it sees how an agent's activity
    evolved over the preceding windows. That temporal shape is information the
    weak labeller never had access to, so it cannot be a shortcut to the label.
    """

    def __init__(self, in_features: int, n_classes: int, hidden: int = 128, layers: int = 1, dropout: float = 0.2, bidirectional: bool = False):
        super().__init__()
        self.input_norm = nn.LayerNorm(in_features)
        self.gru = nn.GRU(
            input_size=in_features,
            hidden_size=hidden,
            num_layers=layers,
            batch_first=True,
            dropout=dropout if layers > 1 else 0.0,
            bidirectional=bidirectional,
        )
        out_dim = hidden * (2 if bidirectional else 1)
        self.head = nn.Sequential(nn.Dropout(dropout), nn.Linear(out_dim, n_classes))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: (batch, seq_len, features)
        output, _ = self.gru(self.input_norm(x))
        return self.head(output[:, -1, :])
