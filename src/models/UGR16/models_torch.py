from __future__ import annotations

import torch.nn as nn


class MLP(nn.Module):
    def __init__(self, in_features: int, n_classes: int, hidden: int = 512, depth: int = 3, dropout: float = 0.2):
        super().__init__()
        layers = []
        d = in_features
        for _ in range(depth):
            layers += [nn.Linear(d, hidden), nn.ReLU(), nn.Dropout(dropout)]
            d = hidden
        layers += [nn.Linear(d, n_classes)]
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)
