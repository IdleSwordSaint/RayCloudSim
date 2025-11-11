"""
Trained GNN-RL policy with Zero-Trust guardrails (DQN-style).

This module provides a lightweight, self-contained DQN implementation that
encodes the graph with a GNN and produces per-node action values. It supports
masking actions via Zero-Trust guardrails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch import Tensor
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv

from .masks import ACTIONS, build_zt_masks


class GNNEncoder(nn.Module):
    def __init__(self, in_dim: int, hidden: int = 64, out_dim: int = 64):
        super().__init__()
        self.g1 = SAGEConv(in_dim, hidden)
        self.g2 = SAGEConv(hidden, out_dim)
        self.act = nn.ReLU()
        self.drop = nn.Dropout(p=0.1)

    def forward(self, x: Tensor, edge_index: Tensor) -> Tensor:
        h = self.act(self.g1(x, edge_index))
        h = self.drop(h)
        h = self.g2(h, edge_index)
        return h


class ActionHead(nn.Module):
    def __init__(self, emb_dim: int, num_actions: int):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(emb_dim, emb_dim),
            nn.ReLU(),
            nn.Linear(emb_dim, num_actions),
        )

    def forward(self, H: Tensor) -> Tensor:
        return self.mlp(H)


@dataclass
class Transition:
    x: Tensor
    edge_index: Tensor
    mask: Tensor
    index_pair: Tuple[int, int]
    reward: float
    next_x: Tensor
    next_edge_index: Tensor
    next_mask: Tensor
    done: bool


class ReplayBuffer:
    def __init__(self, capacity: int = 50_000):
        self.capacity = capacity
        self._data: List[Transition] = []
        self._pos = 0

    def __len__(self) -> int:
        return len(self._data)

    def add(self, t: Transition) -> None:
        if len(self._data) < self.capacity:
            self._data.append(t)
        else:
            self._data[self._pos] = t
        self._pos = (self._pos + 1) % self.capacity

    def sample(self, batch_size: int) -> List[Transition]:
        idx = np.random.choice(len(self._data), size=min(batch_size, len(self._data)), replace=False)
        return [self._data[i] for i in idx]


class ZTADQNPolicy(nn.Module):
    def __init__(self, in_dim: int, num_actions: int, emb_dim: int = 64, lr: float = 1e-3, gamma: float = 0.99, device: str | None = None):
        super().__init__()
        self.device = torch.device(device or ("cuda" if torch.cuda.is_available() else "cpu"))
        self.encoder = GNNEncoder(in_dim, hidden=emb_dim, out_dim=emb_dim)
        self.head = ActionHead(emb_dim, num_actions)
        self.tgt_encoder = GNNEncoder(in_dim, hidden=emb_dim, out_dim=emb_dim)
        self.tgt_head = ActionHead(emb_dim, num_actions)
        self.gamma = gamma
        self.to(self.device)
        self._sync_target()

        self.optim = optim.Adam(self.parameters(), lr=lr)
        self.loss_fn = nn.SmoothL1Loss(reduction="mean")

    def _sync_target(self) -> None:
        self.tgt_encoder.load_state_dict(self.encoder.state_dict())
        self.tgt_head.load_state_dict(self.head.state_dict())

    def _forward_q(self, x: Tensor, edge_index: Tensor) -> Tensor:
        H = self.encoder(x, edge_index)
        Q = self.head(H)
        return Q

    @torch.no_grad()
    def _forward_q_target(self, x: Tensor, edge_index: Tensor) -> Tensor:
        H = self.tgt_encoder(x, edge_index)
        Q = self.tgt_head(H)
        return Q

    def build_graph_tensors(self, nodes_features: List[Dict[str, float]], edge_list: Sequence[Tuple[int, int]]) -> Tuple[Tensor, Tensor]:
        # Node feature tensor
        keys = list(nodes_features[0].keys()) if nodes_features else []
        F = len(keys)
        X = torch.zeros((len(nodes_features), F), dtype=torch.float32)
        for i, feat in enumerate(nodes_features):
            X[i] = torch.tensor([float(feat[k]) for k in keys], dtype=torch.float32)
        # Edge index tensor
        if len(edge_list):
            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)
        return X.to(self.device), edge_index.to(self.device)

    @staticmethod
    def apply_mask(Q: Tensor, M: Tensor) -> Tensor:
        # Q: [N, A], M: [N, A]
        very_neg = torch.tensor(-1e9, device=Q.device, dtype=Q.dtype)
        return Q + (1.0 - M) * very_neg

    @torch.no_grad()
    def select(self, nodes_features: List[Dict[str, float]], edge_list: Sequence[Tuple[int, int]], system_state: Dict[str, str], epsilon: float = 0.1) -> Tuple[Tuple[int, int], Dict[str, Any]]:
        X, EI = self.build_graph_tensors(nodes_features, edge_list)
        Q = self._forward_q(X, EI)

        # Build masks and apply
        M_np = build_zt_masks(nodes_features, system_state)
        M = torch.from_numpy(M_np).to(Q.device)
        Qm = self.apply_mask(Q, M)

        N, A = Qm.shape
        if np.random.rand() < epsilon:
            # Random valid choice
            valid = (M > 0).nonzero(as_tuple=False)
            idx = valid[np.random.randint(0, valid.shape[0])]
            v_idx, a_idx = int(idx[0].item()), int(idx[1].item())
        else:
            flat_idx = int(torch.argmax(Qm).item())
            v_idx, a_idx = flat_idx // A, flat_idx % A

        return (v_idx, a_idx), {"Q": Qm.detach().cpu(), "mask": M.detach().cpu()}

    def learn(self, batch: List[Transition]) -> Dict[str, float]:
        if not batch:
            return {"loss": 0.0}

        losses = []
        for t in batch:
            x, ei, M = t.x.to(self.device), t.edge_index.to(self.device), t.mask.to(self.device)
            nx, nei, nM = t.next_x.to(self.device), t.next_edge_index.to(self.device), t.next_mask.to(self.device)
            v_idx, a_idx = t.index_pair

            # Current Q
            Q = self._forward_q(x, ei)
            Qm = self.apply_mask(Q, M)
            q_sa = Qm[v_idx, a_idx]

            # Target Q
            with torch.no_grad():
                Q_next = self._forward_q_target(nx, nei)
                Qn_masked = self.apply_mask(Q_next, nM)
                max_next = torch.max(Qn_masked) if not t.done else torch.tensor(0.0, device=Q.device)
                target = torch.tensor(t.reward, device=Q.device) + self.gamma * max_next

            loss = self.loss_fn(q_sa, target)
            self.optim.zero_grad(set_to_none=True)
            loss.backward()
            nn.utils.clip_grad_norm_(self.parameters(), max_norm=2.0)
            self.optim.step()
            losses.append(float(loss.detach().cpu().item()))

        # Periodically sync target network
        self._sync_target()
        return {"loss": float(np.mean(losses)) if losses else 0.0}


__all__ = [
    "GNNEncoder",
    "ActionHead",
    "ReplayBuffer",
    "Transition",
    "ZTADQNPolicy",
]
