#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import torch
import torch.nn as nn


class TorchLogReg(nn.Module):
    """Logistic Regression en PyTorch: lineal + logits."""
    def __init__(self, in_features: int, n_classes: int = 2):
        super().__init__()
        self.linear = nn.Linear(in_features, n_classes)

    def forward(self, x):
        return self.linear(x)


class MLP(nn.Module):
    def __init__(self, in_features: int, n_classes: int, hidden: int = 512, depth: int = 3, dropout: float = 0.2):
        super().__init__()
        layers = []
        d = in_features
        for i in range(depth):
            layers += [nn.Linear(d, hidden), nn.ReLU(), nn.Dropout(dropout)]
            d = hidden
        layers += [nn.Linear(d, n_classes)]
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class FTTransformer(nn.Module):
    """
    FT-Transformer minimal para SOLO features numéricas:
    - cada feature escalar -> token embedding via Linear(1->d_model)
    - transformer encoder sobre tokens
    - pooling mean
    - head
    """
    def __init__(self, n_features: int | None = None, n_classes: int = 2, d_model: int = 128, n_heads: int = 8, n_layers: int = 4, dropout: float = 0.1, *, in_features: int | None = None):
        super().__init__()
        self.n_features = n_features
        self.d_model = d_model

        self.feature_proj = nn.ModuleList([nn.Linear(1, d_model) for _ in range(n_features)])
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=n_heads, dim_feedforward=d_model * 4, dropout=dropout, batch_first=True)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Sequential(nn.Linear(d_model, d_model), nn.ReLU(), nn.Dropout(dropout), nn.Linear(d_model, n_classes))

    def forward(self, x):
        # x: (B, F)
        tokens = []
        for i in range(self.n_features):
            xi = x[:, i:i+1]  # (B,1)
            tokens.append(self.feature_proj[i](xi).unsqueeze(1))  # (B,1,D)
        t = torch.cat(tokens, dim=1)  # (B,F,D)
        z = self.encoder(t)
        z = self.norm(z)
        pooled = z.mean(dim=1)  # (B,D)
        return self.head(pooled)


class GRUClassifier(nn.Module):
    def __init__(self, n_features: int, n_classes: int = 2, hidden: int = 128, n_layers: int = 2, dropout: float = 0.1, bidirectional: bool = False):
        super().__init__()
        self.gru = nn.GRU(
            input_size=n_features,
            hidden_size=hidden,
            num_layers=n_layers,
            dropout=dropout if n_layers > 1 else 0.0,
            batch_first=True,
            bidirectional=bidirectional,
        )
        out_dim = hidden * (2 if bidirectional else 1)
        self.head = nn.Sequential(nn.Linear(out_dim, out_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(out_dim, n_classes))

    def forward(self, x):
        # x: (B, T, F)
        out, h = self.gru(x)
        last = out[:, -1, :]  # último timestep
        return self.head(last)


class LSTMClassifier(nn.Module):
    def __init__(self, n_features: int, n_classes: int = 2, hidden: int = 128, n_layers: int = 2, dropout: float = 0.1, bidirectional: bool = False):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=n_features,
            hidden_size=hidden,
            num_layers=n_layers,
            dropout=dropout if n_layers > 1 else 0.0,
            batch_first=True,
            bidirectional=bidirectional,
        )
        out_dim = hidden * (2 if bidirectional else 1)
        self.head = nn.Sequential(nn.Linear(out_dim, out_dim), nn.ReLU(), nn.Dropout(dropout), nn.Linear(out_dim, n_classes))

    def forward(self, x):
        out, _ = self.lstm(x)
        last = out[:, -1, :]
        return self.head(last)


class Autoencoder(nn.Module):
    def __init__(self, in_features: int, hidden: int = 256, depth: int = 3, dropout: float = 0.1):
        super().__init__()
        enc = []
        d = in_features
        for _ in range(depth):
            enc += [nn.Linear(d, hidden), nn.ReLU(), nn.Dropout(dropout)]
            d = hidden
            hidden = max(hidden // 2, 32)
        self.encoder = nn.Sequential(*enc)

        dec = []
        for _ in range(depth - 1):
            dec += [nn.Linear(d, d * 2), nn.ReLU(), nn.Dropout(dropout)]
            d = d * 2
        dec += [nn.Linear(d, in_features)]
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)