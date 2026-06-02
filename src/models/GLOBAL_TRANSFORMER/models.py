#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import torch
import torch.nn as nn


class NumericFeatureTokenizer(nn.Module):
    def __init__(self, n_features: int, d_model: int, dropout: float) -> None:
        super().__init__()
        self.weight = nn.Parameter(torch.empty(n_features, d_model))
        self.bias = nn.Parameter(torch.zeros(n_features, d_model))
        self.feature_embedding = nn.Parameter(torch.empty(n_features, d_model))
        self.dropout = nn.Dropout(dropout)
        nn.init.xavier_uniform_(self.weight)
        nn.init.normal_(self.feature_embedding, std=0.02)

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        tokens = features.unsqueeze(-1) * self.weight.unsqueeze(0) + self.bias.unsqueeze(0)
        tokens = tokens + self.feature_embedding.unsqueeze(0)
        return self.dropout(tokens)


class GlobalFTTransformer(nn.Module):
    def __init__(
        self,
        n_features: int,
        n_datasets: int,
        d_model: int = 128,
        n_layers: int = 3,
        n_heads: int = 4,
        dropout: float = 0.2,
        ff_multiplier: int = 4,
        use_dataset_embedding: bool = True,
    ) -> None:
        super().__init__()
        self.use_dataset_embedding = use_dataset_embedding
        self.tokenizer = NumericFeatureTokenizer(n_features=n_features, d_model=d_model, dropout=dropout)
        self.cls_token = nn.Parameter(torch.zeros(1, 1, d_model))
        self.dataset_embedding = nn.Embedding(max(1, n_datasets), d_model) if use_dataset_embedding else None
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=d_model * ff_multiplier,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)
        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, 2),
        )
        nn.init.normal_(self.cls_token, std=0.02)

    def forward(self, features: torch.Tensor, dataset_id: torch.Tensor | None = None) -> torch.Tensor:
        feature_tokens = self.tokenizer(features)
        batch_size = features.shape[0]
        cls = self.cls_token.expand(batch_size, -1, -1)
        tokens = torch.cat([cls, feature_tokens], dim=1)
        if self.use_dataset_embedding and self.dataset_embedding is not None and dataset_id is not None:
            dataset_token = self.dataset_embedding(dataset_id).unsqueeze(1)
            tokens = torch.cat([tokens[:, :1, :] + dataset_token, tokens[:, 1:, :]], dim=1)
        encoded = self.encoder(tokens)
        cls_encoded = self.norm(encoded[:, 0, :])
        return self.head(cls_encoded)