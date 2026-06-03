"""
edge_architecture.py
====================
次世代エッジ分散アーキテクチャ サンプル実装
Edge Distributed Architecture - Prototype

概要:
  アプリサービス × 通信 × エッジサーバーの統合モデルを
  単一ファイルで示すプロトタイプ実装。

カテゴリ分類:
  [CAT-1] データ構造・定数定義
  [CAT-2] 暗号・Hash認証レイヤー   (Merkle Tree / SHA-256)
  [CAT-3] ノード管理               (レイテンシ計測・登録)
  [CAT-4] スコアエンジン           (信頼スコア + コスト差分)
  [CAT-5] CRDT同期エンジン         (Vector Clock / 差分マージ)
  [CAT-6] サイドロードマネージャー (対象分類・ロード判定)
  [CAT-7] バックアップエンジン     (WAL / スナップショット)
  [CAT-8] エッジルーター           (最適ノード選択)
  [CAT-9] APIレイヤー              (統合インターフェース)

処理構造:
  branch_*  : 分岐処理  (判定・分類・条件評価)
  process_* : 主要処理  (実行・変換・状態変更)
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("EdgeArch")


# =============================================================================
# [CAT-1] データ構造・定数定義
# =============================================================================

class NodeTier(Enum):
    """ノード層の定義"""
    LOCAL   = auto()   # ローカルクラスター（最優先）
    EDGE    = auto()   # エッジサーバー
    CENTER  = auto()   # センターサーバー（フォールバック）


class TrustLevel(Enum):
    """サイドロード対象の信頼分類"""
    HIGH    = "high"    # 自動実行可
    MEDIUM  = "medium"  # スコア審査
    LOW     = "low"     # 拒否


class SyncStatus(Enum):
    """同期状態"""
    ONLINE   = "online"
    OFFLINE  = "offline"
    SYNCING  = "syncing"
    CONFLICT = "conflict"


# コスト単価（月次・円）
COST_PER_USER_LOCAL  =    0   # 償却済み
COST_PER_USER_EDGE   =  200   # エッジノード利用料
COST_PER_USER_CENTER = 1200   # センター利用料

# カウントフリー収益
COUNT_FREE_REVENUE_PER_USER = 500

# 広告ARPU（月次）
AD_ARPU_PER_USER = 150

# スコア閾値
SCORE_THRESHOLD_AUTO   = 0.75   # 自動実行
SCORE_THRESHOLD_REVIEW = 0.45   # 要審査
# 上記未満は拒否


@dataclass
class Node:
    """ノード情報"""
    node_id:    str
    tier:       NodeTier
    address:    str
    latency_ms: float = 0.0
    cpu_usage:  float = 0.0        # 0.0〜1.0
    trust_score: float = 1.0       # 0.0〜1.0
    is_online:  bool = True
    cost_per_unit: float = 0.0


@dataclass
class Package:
    """サイドロード対象パッケージ"""
    package_id:   str
    name:         str
    version:      str
    content_hash: str
    signature:    str
    trust_level:  TrustLevel
    size_bytes:   int
    source_node:  str


@dataclass
class DataEntry:
    """データエントリ（中身は不透明・メタデータのみ扱う）"""
    entry_id:   str
    meta_hash:  str                # データ本体のHash（中身は見ない）
    size_bytes: int
    updated_at: float
    node_id:    str
    vector_clock: Dict[str, int] = field(default_factory=dict)


@dataclass
class WALRecord:
    """Write-Ahead Logエントリ"""
    record_id:  str
    entry_id:   str
    operation:  str                # "write" | "delete" | "update"
    meta_hash:  str
    timestamp:  float
    node_id:    str
    applied:    bool = False


@dataclass
class SyncResult:
    """同期結果"""
    success:       bool
    merged_count:  int
    conflict_count: int
    status:        SyncStatus
    message:       str


# =============================================================================
# [CAT-2] 暗号・Hash認証レイヤー
# =============================================================================

class HashLayer:
    """
    SHA-256 ベースのHash認証とMerkle Tree実装。
    データの中身を見ずに整合性を検証する。
    """

    # ---- 主要処理 ----

    @staticmethod
    def process_sha256(data: str) -> str:
        """SHA-256 Hashを計算する"""
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def process_build_merkle_tree(hashes: List[str]) -> List[List[str]]:
        """
        Merkle Treeを構築する。
        葉ノードのHashリストからRootHashまでを生成。
        """
        if not hashes:
            return [[HashLayer.process_sha256("empty")]]

        tree: List[List[str]] = [hashes[:]]
        current = hashes[:]

        while len(current) > 1:
            # 奇数個の場合は最後の要素を複製
            if len(current) % 2 == 1:
                current.append(current[-1])
            parent = []
            for i in range(0, len(current), 2):
                combined = current[i] + current[i + 1]
                parent.append(HashLayer.process_sha256(combined))
            tree.append(parent)
            current = parent

        return tree

    @staticmethod
    def process_get_root_hash(tree: List[List[str]]) -> str:
        """Merkle TreeのRootHashを取得する"""
        if not tree:
            return ""
        return tree[-1][0]

    @staticmethod
    def process_verify_signature(package: Package) -> bool:
        """
        パッケージ署名を検証する（簡易実装）。
        実運用ではRSA/ECDSA等の非対称暗号を使用。
        """
        expected = HashLayer.process_sha256(
            package.package_id + package.version + package.content_hash
        )
        return expected == package.signature

    # ---- 分岐処理 ----

    @staticmethod
    def branch_hash_matches(data: str, expected_hash: str) -> bool:
        """データのHashが期待値と一致するか判定"""
        actual = HashLayer.process_sha256(data)
        return actual == expected_hash

    @staticmethod
    def branch_is_root_consistent(
        local_root: str, remote_root: str
    ) -> bool:
        """ローカルとリモートのRootHashが一致するか判定"""
        return local_root == remote_root


# =============================================================================
# [CAT-3] ノード管理
# =============================================================================

class NodeRegistry:
    """
    ノードの登録・状態管理・レイテンシ計測を行う。
    """

    def __init__(self):
        self._nodes: Dict[str, Node] = {}

    # ---- 主要処理 ----

    def process_register(self, node: Node) -> None:
        """ノードを登録する"""
        self._nodes[node.node_id] = node
        log.info(f"Node registered: {node.node_id} ({node.tier.name})")

    def process_measure_latency(self, node_id: str) -> float:
        """
        レイテンシを計測する（プロトタイプ：シミュレーション値）。
        実運用ではICMP ping or TCPソケット計測を使用。
        """
        tier_latency = {
            NodeTier.LOCAL:  random.uniform(0.1,  2.0),
            NodeTier.EDGE:   random.uniform(2.0, 15.0),
            NodeTier.CENTER: random.uniform(20.0, 80.0),
        }
        node = self._nodes.get(node_id)
        if not node:
            return 9999.0
        latency = tier_latency[node.tier]
        node.latency_ms = latency
        return latency

    def process_update_status(
        self, node_id: str, is_online: bool, cpu_usage: float
    ) -> None:
        """ノードの稼働状態を更新する"""
        node = self._nodes.get(node_id)
        if node:
            node.is_online  = is_online
            node.cpu_usage  = cpu_usage

    def process_refresh_all_latencies(self) -> Dict[str, float]:
        """全ノードのレイテンシを一括更新する"""
        return {
            nid: self.process_measure_latency(nid)
            for nid in self._nodes
        }

    # ---- 分岐処理 ----

    def branch_is_node_available(self, node_id: str) -> bool:
        """ノードが利用可能かどうか判定"""
        node = self._nodes.get(node_id)
        return bool(node and node.is_online and node.cpu_usage < 0.9)

    def branch_get_nodes_by_tier(self, tier: NodeTier) -> List[Node]:
        """指定層のノードリストを取得"""
        return [n for n in self._nodes.values() if n.tier == tier]

    def branch_has_local_node(self) -> bool:
        """ローカルノードが存在するか確認"""
        return any(
            n.tier == NodeTier.LOCAL and n.is_online
            for n in self._nodes.values()
        )

    def get(self, node_id: str) -> Optional[Node]:
        return self._nodes.get(node_id)

    def all_nodes(self) -> List[Node]:
        return list(self._nodes.values())


# =============================================================================
# [CAT-4] スコアエンジン
# =============================================================================

class ScoreEngine:
    """
    信頼スコアとコスト差分を統合した評価エンジン。
    セキュリティ判断と経済合理性を同一フレームワークで扱う。

    TrustScore =
        署名検証スコア    × 0.30
        + 出所信頼度      × 0.25
        + 過去実績        × 0.20
        + リソース影響度  × 0.15
        + コスト差分      × 0.10
    """

    WEIGHTS = {
        "signature":    0.30,
        "source":       0.25,
        "history":      0.20,
        "resource":     0.15,
        "cost_diff":    0.10,
    }

    def __init__(self, registry: NodeRegistry):
        self._registry = registry
        self._history: Dict[str, List[float]] = defaultdict(list)

    # ---- 主要処理 ----

    def process_score_package(self, package: Package, node: Node) -> float:
        """パッケージの総合スコアを算出する"""
        sig_score      = self._calc_signature_score(package)
        source_score   = node.trust_score
        history_score  = self._calc_history_score(package.package_id)
        resource_score = self._calc_resource_score(node)
        cost_score     = self._calc_cost_diff_score(node)

        total = (
            sig_score      * self.WEIGHTS["signature"]
            + source_score   * self.WEIGHTS["source"]
            + history_score  * self.WEIGHTS["history"]
            + resource_score * self.WEIGHTS["resource"]
            + cost_score     * self.WEIGHTS["cost_diff"]
        )
        log.debug(
            f"Score [{package.name}]: sig={sig_score:.2f} "
            f"src={source_score:.2f} hist={history_score:.2f} "
            f"res={resource_score:.2f} cost={cost_score:.2f} "
            f"→ total={total:.2f}"
        )
        return round(total, 4)

    def process_record_history(self, package_id: str, score: float) -> None:
        """スコア履歴を記録（学習型スコアリングの基盤）"""
        self._history[package_id].append(score)
        # 直近100件のみ保持
        self._history[package_id] = self._history[package_id][-100:]

    def process_calc_business_score(self, user_count: int) -> Dict[str, Any]:
        """
        ユーザー規模に応じたビジネス収支スコアを算出する。
        広告収入 + カウントフリー収益 - インフラコストを評価。
        """
        ad_revenue        = user_count * AD_ARPU_PER_USER
        count_free_rev    = user_count * COUNT_FREE_REVENUE_PER_USER
        total_revenue     = ad_revenue + count_free_rev

        # エッジ化でセンタートラフィックを75%削減と仮定
        infra_cost_raw    = user_count * COST_PER_USER_CENTER
        infra_cost_edge   = infra_cost_raw * 0.25   # 75%削減
        center_fixed      = max(50_000, user_count * 5)

        total_cost        = infra_cost_edge + center_fixed
        profit            = total_revenue - total_cost
        margin            = profit / total_revenue if total_revenue > 0 else 0

        return {
            "user_count":        user_count,
            "ad_revenue":        ad_revenue,
            "count_free_revenue": count_free_rev,
            "total_revenue":     total_revenue,
            "infra_cost":        total_cost,
            "profit":            profit,
            "margin_pct":        round(margin * 100, 1),
        }

    # ---- 分岐処理 ----

    def branch_classify_score(self, score: float) -> TrustLevel:
        """スコア値を信頼レベルに分類する"""
        if score >= SCORE_THRESHOLD_AUTO:
            return TrustLevel.HIGH
        elif score >= SCORE_THRESHOLD_REVIEW:
            return TrustLevel.MEDIUM
        else:
            return TrustLevel.LOW

    def branch_should_auto_execute(self, score: float) -> bool:
        """自動実行可能かどうかを判定"""
        return score >= SCORE_THRESHOLD_AUTO

    def branch_is_profitable(self, user_count: int) -> bool:
        """ユーザー規模で黒字になるかを判定"""
        result = self.process_calc_business_score(user_count)
        return result["profit"] > 0

    # ---- 内部計算 ----

    def _calc_signature_score(self, package: Package) -> float:
        if not HashLayer.process_verify_signature(package):
            return 0.0
        trust_map = {
            TrustLevel.HIGH:   1.0,
            TrustLevel.MEDIUM: 0.6,
            TrustLevel.LOW:    0.2,
        }
        return trust_map[package.trust_level]

    def _calc_history_score(self, package_id: str) -> float:
        records = self._history.get(package_id, [])
        if not records:
            return 0.7   # 実績なしはデフォルト値
        return round(sum(records) / len(records), 4)

    def _calc_resource_score(self, node: Node) -> float:
        # CPU使用率が低いほどスコア高
        return round(1.0 - node.cpu_usage, 4)

    def _calc_cost_diff_score(self, node: Node) -> float:
        # ローカルが最高スコア
        tier_score = {
            NodeTier.LOCAL:  1.0,
            NodeTier.EDGE:   0.6,
            NodeTier.CENTER: 0.2,
        }
        return tier_score.get(node.tier, 0.0)


# =============================================================================
# [CAT-5] CRDT同期エンジン
# =============================================================================

class CRDTSyncEngine:
    """
    Vector Clock + CRDT によるオフライン対応データ同期エンジン。
    切断中の操作を WAL に蓄積し、再接続時に自動マージする。
    """

    def __init__(self, local_node_id: str):
        self.node_id    = local_node_id
        self._store:    Dict[str, DataEntry]  = {}
        self._wal:      List[WALRecord]       = []
        self._clock:    Dict[str, int]        = defaultdict(int)
        self.status:    SyncStatus            = SyncStatus.ONLINE

    # ---- 主要処理 ----

    def process_write(self, entry_id: str, meta_hash: str, size_bytes: int) -> DataEntry:
        """
        データエントリを書き込む。
        中身は見ず、Hashとメタデータのみを管理する。
        """
        self._clock[self.node_id] += 1
        entry = DataEntry(
            entry_id    = entry_id,
            meta_hash   = meta_hash,
            size_bytes  = size_bytes,
            updated_at  = time.time(),
            node_id     = self.node_id,
            vector_clock = dict(self._clock),
        )
        self._store[entry_id] = entry
        self._wal.append(WALRecord(
            record_id  = str(uuid.uuid4()),
            entry_id   = entry_id,
            operation  = "write",
            meta_hash  = meta_hash,
            timestamp  = entry.updated_at,
            node_id    = self.node_id,
        ))
        return entry

    def process_merge(self, remote_entries: List[DataEntry]) -> SyncResult:
        """
        リモートエントリとマージする（CRDT Last-Write-Wins）。
        Vector Clockで競合を検出し自動解決する。
        """
        merged = 0
        conflicts = 0

        for remote in remote_entries:
            local = self._store.get(remote.entry_id)

            if local is None:
                # ローカルにない → そのまま取り込み
                self._store[remote.entry_id] = remote
                merged += 1

            elif self.branch_is_newer(remote.vector_clock, local.vector_clock):
                # リモートが新しい → 上書き
                self._store[remote.entry_id] = remote
                merged += 1

            elif self.branch_is_concurrent(remote.vector_clock, local.vector_clock):
                # 同時更新（競合） → Last-Write-Wins で解決
                conflicts += 1
                if remote.updated_at > local.updated_at:
                    self._store[remote.entry_id] = remote
                    merged += 1
                log.warning(f"CRDT conflict resolved for {remote.entry_id}")

        # マージ済みWALをクリア
        self._wal = [r for r in self._wal if not r.applied]

        return SyncResult(
            success       = True,
            merged_count  = merged,
            conflict_count= conflicts,
            status        = SyncStatus.ONLINE,
            message       = f"Merged {merged} entries, {conflicts} conflicts resolved",
        )

    def process_build_local_merkle(self) -> Tuple[List[List[str]], str]:
        """ローカルストアのMerkle Treeを構築しRootHashを返す"""
        hashes = [e.meta_hash for e in sorted(
            self._store.values(), key=lambda x: x.entry_id
        )]
        tree = HashLayer.process_build_merkle_tree(hashes)
        root = HashLayer.process_get_root_hash(tree)
        return tree, root

    def process_get_pending_wal(self) -> List[WALRecord]:
        """未適用のWALレコードを取得する"""
        return [r for r in self._wal if not r.applied]

    def process_go_offline(self) -> None:
        """オフラインモードへ移行する"""
        self.status = SyncStatus.OFFLINE
        log.info(f"Node {self.node_id} → OFFLINE mode")

    def process_reconnect(self, remote_entries: List[DataEntry]) -> SyncResult:
        """再接続時の同期フローを実行する"""
        self.status = SyncStatus.SYNCING
        log.info(f"Node {self.node_id} reconnecting, WAL={len(self._wal)} records")
        result = self.process_merge(remote_entries)
        self.status = SyncStatus.ONLINE
        log.info(f"Reconnect complete: {result.message}")
        return result

    # ---- 分岐処理 ----

    def branch_is_newer(
        self, vc_a: Dict[str, int], vc_b: Dict[str, int]
    ) -> bool:
        """vc_a が vc_b より新しいかを判定（Vector Clock比較）"""
        all_keys = set(vc_a) | set(vc_b)
        return (
            all(vc_a.get(k, 0) >= vc_b.get(k, 0) for k in all_keys)
            and any(vc_a.get(k, 0)  > vc_b.get(k, 0) for k in all_keys)
        )

    def branch_is_concurrent(
        self, vc_a: Dict[str, int], vc_b: Dict[str, int]
    ) -> bool:
        """vc_a と vc_b が同時更新（競合）かを判定"""
        all_keys = set(vc_a) | set(vc_b)
        a_newer_in_some = any(vc_a.get(k, 0) > vc_b.get(k, 0) for k in all_keys)
        b_newer_in_some = any(vc_b.get(k, 0) > vc_a.get(k, 0) for k in all_keys)
        return a_newer_in_some and b_newer_in_some

    def branch_needs_sync(self, remote_root: str) -> bool:
        """リモートとの同期が必要かどうかを判定"""
        _, local_root = self.process_build_local_merkle()
        return not HashLayer.branch_is_root_consistent(local_root, remote_root)

    def branch_is_offline(self) -> bool:
        """オフライン状態かどうか確認"""
        return self.status == SyncStatus.OFFLINE


# =============================================================================
# [CAT-6] サイドロードマネージャー
# =============================================================================

class SideloadManager:
    """
    「何を」サイドロードするかを評価し、
    スコアエンジンと連携してロード判定を行う。
    """

    # 高信頼対象パターン（名前ベースの簡易判定）
    HIGH_TRUST_PATTERNS = [
        "backup_agent", "monitor", "config", "diff_patch", "metadata"
    ]

    # 禁止対象パターン
    BLOCKED_PATTERNS = [
        "kernel_module", "unsigned_binary", "auth_core", "root_process"
    ]

    def __init__(self, score_engine: ScoreEngine, registry: NodeRegistry):
        self._scorer   = score_engine
        self._registry = registry

    # ---- 主要処理 ----

    def process_evaluate(
        self, package: Package, source_node_id: str
    ) -> Tuple[float, TrustLevel, str]:
        """
        パッケージを評価し（スコア, 信頼レベル, 理由）を返す。
        """
        # まず禁止パターンチェック
        if self.branch_is_blocked(package.name):
            return 0.0, TrustLevel.LOW, f"Blocked pattern: {package.name}"

        node = self._registry.get(source_node_id)
        if not node:
            return 0.0, TrustLevel.LOW, "Source node not found"

        if not self._registry.branch_is_node_available(source_node_id):
            return 0.0, TrustLevel.LOW, "Source node unavailable"

        score = self._scorer.process_score_package(package, node)
        level = self._scorer.branch_classify_score(score)
        self._scorer.process_record_history(package.package_id, score)

        reason = (
            f"Score={score:.3f} | Tier={node.tier.name} | "
            f"Latency={node.latency_ms:.1f}ms"
        )
        return score, level, reason

    def process_load(
        self, package: Package, source_node_id: str
    ) -> Dict[str, Any]:
        """
        ロード実行。スコアに応じて自動実行/審査待ち/拒否に分岐。
        """
        score, level, reason = self.process_evaluate(package, source_node_id)

        result: Dict[str, Any] = {
            "package_id": package.package_id,
            "name":       package.name,
            "score":      score,
            "level":      level.value,
            "reason":     reason,
            "action":     None,
        }

        # ---- 分岐：アクション決定 ----
        if self.branch_is_blocked(package.name):
            result["action"] = "REJECTED"
            log.warning(f"[SIDELOAD] REJECTED {package.name}: {reason}")

        elif self._scorer.branch_should_auto_execute(score):
            result["action"] = "EXECUTED"
            log.info(f"[SIDELOAD] EXECUTED {package.name}: {reason}")

        elif level == TrustLevel.MEDIUM:
            result["action"] = "PENDING_REVIEW"
            log.info(f"[SIDELOAD] PENDING_REVIEW {package.name}: {reason}")

        else:
            result["action"] = "REJECTED"
            log.warning(f"[SIDELOAD] REJECTED {package.name}: {reason}")

        return result

    # ---- 分岐処理 ----

    def branch_is_blocked(self, name: str) -> bool:
        """禁止対象パターンに該当するか判定"""
        name_lower = name.lower()
        return any(p in name_lower for p in self.BLOCKED_PATTERNS)

    def branch_is_high_trust(self, name: str) -> bool:
        """高信頼パターンに該当するか判定"""
        name_lower = name.lower()
        return any(p in name_lower for p in self.HIGH_TRUST_PATTERNS)

    def branch_requires_review(self, score: float, level: TrustLevel) -> bool:
        """人間による審査が必要かどうか判定"""
        return level == TrustLevel.MEDIUM and score < SCORE_THRESHOLD_AUTO


# =============================================================================
# [CAT-7] バックアップエンジン
# =============================================================================

class BackupEngine:
    """
    WAL・スナップショット・多層ミラーリングによるバックアップエンジン。
    データの中身を見ずにHashベースで整合性を管理する。
    """

    def __init__(self, node_id: str):
        self.node_id    = node_id
        self._snapshots: List[Dict[str, Any]] = []
        self._replicas:  Dict[str, Dict[str, str]] = {}  # node_id → {entry_id: hash}

    # ---- 主要処理 ----

    def process_snapshot(
        self, store: Dict[str, DataEntry]
    ) -> Dict[str, Any]:
        """
        現時点のストア状態をスナップショットとして保存する。
        """
        hashes = [e.meta_hash for e in store.values()]
        tree   = HashLayer.process_build_merkle_tree(hashes)
        root   = HashLayer.process_get_root_hash(tree)

        snap = {
            "snapshot_id": str(uuid.uuid4()),
            "timestamp":   time.time(),
            "entry_count": len(store),
            "root_hash":   root,
            "entry_hashes": {eid: e.meta_hash for eid, e in store.items()},
        }
        self._snapshots.append(snap)
        log.info(
            f"[BACKUP] Snapshot created: {snap['snapshot_id'][:8]}… "
            f"entries={snap['entry_count']} root={root[:12]}…"
        )
        return snap

    def process_replicate(
        self, target_node_id: str, store: Dict[str, DataEntry]
    ) -> bool:
        """
        ターゲットノードへメタデータをレプリケートする。
        実運用ではネットワーク転送を行う部分。
        """
        self._replicas[target_node_id] = {
            eid: e.meta_hash for eid, e in store.items()
        }
        log.info(
            f"[BACKUP] Replicated {len(store)} entries "
            f"→ {target_node_id}"
        )
        return True

    def process_prune_snapshots(self, keep_count: int = 5) -> int:
        """古いスナップショットを削除してストレージ膨張を防ぐ"""
        removed = max(0, len(self._snapshots) - keep_count)
        self._snapshots = self._snapshots[-keep_count:]
        if removed > 0:
            log.info(f"[BACKUP] Pruned {removed} old snapshots")
        return removed

    def process_verify_replica(
        self, target_node_id: str, store: Dict[str, DataEntry]
    ) -> bool:
        """レプリカの整合性を検証する"""
        replica = self._replicas.get(target_node_id)
        if not replica:
            return False
        for eid, entry in store.items():
            if replica.get(eid) != entry.meta_hash:
                log.warning(f"[BACKUP] Replica mismatch for {eid}")
                return False
        return True

    # ---- 分岐処理 ----

    def branch_needs_snapshot(self, wal_count: int, interval_sec: float = 60.0) -> bool:
        """スナップショット取得が必要かを判定"""
        if not self._snapshots:
            return True
        last_ts = self._snapshots[-1]["timestamp"]
        time_due = (time.time() - last_ts) >= interval_sec
        wal_due  = wal_count >= 50
        return time_due or wal_due

    def branch_replica_is_stale(
        self, target_node_id: str, store: Dict[str, DataEntry]
    ) -> bool:
        """レプリカが古い（更新が必要）かどうかを判定"""
        return not self.process_verify_replica(target_node_id, store)

    def branch_has_valid_snapshot(self) -> bool:
        """有効なスナップショットが存在するかを確認"""
        return len(self._snapshots) > 0

    def get_latest_snapshot(self) -> Optional[Dict[str, Any]]:
        """最新スナップショットを取得"""
        return self._snapshots[-1] if self._snapshots else None


# =============================================================================
# [CAT-8] エッジルーター
# =============================================================================

class EdgeRouter:
    """
    レイテンシ・スコア・コストを統合して
    最適なノードを選択するルーター。
    """

    def __init__(self, registry: NodeRegistry, score_engine: ScoreEngine):
        self._registry = registry
        self._scorer   = score_engine

    # ---- 主要処理 ----

    def process_select_best_node(
        self, prefer_tier: Optional[NodeTier] = None
    ) -> Optional[Node]:
        """
        利用可能なノードの中から最適なものを選択する。
        ローカル → エッジ → センターの優先順。
        """
        candidates = [
            n for n in self._registry.all_nodes()
            if self._registry.branch_is_node_available(n.node_id)
        ]
        if not candidates:
            log.error("[ROUTER] No available nodes")
            return None

        # 優先tierが指定されている場合はフィルタ
        if prefer_tier:
            tier_nodes = [n for n in candidates if n.tier == prefer_tier]
            if tier_nodes:
                candidates = tier_nodes

        # スコア計算（レイテンシ + 信頼スコア + コスト）
        def node_score(node: Node) -> float:
            latency_score = 1.0 / (1.0 + node.latency_ms / 10.0)
            cost_score    = self._scorer._calc_cost_diff_score(node)
            return latency_score * 0.5 + node.trust_score * 0.3 + cost_score * 0.2

        best = max(candidates, key=node_score)
        log.info(
            f"[ROUTER] Selected: {best.node_id} "
            f"({best.tier.name}) latency={best.latency_ms:.1f}ms"
        )
        return best

    def process_select_with_fallback(self) -> List[Node]:
        """
        優先ノードから順に候補リストを返す（フォールバック用）。
        """
        result = []
        for tier in [NodeTier.LOCAL, NodeTier.EDGE, NodeTier.CENTER]:
            nodes = [
                n for n in self._registry.branch_get_nodes_by_tier(tier)
                if self._registry.branch_is_node_available(n.node_id)
            ]
            nodes.sort(key=lambda n: n.latency_ms)
            result.extend(nodes)
        return result

    # ---- 分岐処理 ----

    def branch_should_use_local(self) -> bool:
        """ローカルノードを優先すべきかを判定"""
        return self._registry.branch_has_local_node()

    def branch_is_wifi_available(self) -> bool:
        """
        公衆WiFi接続が利用可能かを判定（簡易シミュレーション）。
        実運用ではネットワークインターフェース情報を参照。
        """
        return random.random() > 0.3   # 70%の確率でWiFi利用可能

    def branch_select_connection_mode(self) -> str:
        """
        接続モードを選択する。
        LOCAL > WIFI+EDGE > MOBILE+EDGE > CENTER
        """
        if self.branch_should_use_local():
            return "LOCAL"
        elif self.branch_is_wifi_available():
            return "WIFI_EDGE"
        else:
            return "MOBILE_EDGE"


# =============================================================================
# [CAT-9] APIレイヤー（統合インターフェース）
# =============================================================================

class EdgeArchAPI:
    """
    全コンポーネントを統合するAPIレイヤー。
    アプリ開発者がバックアップ・同期・サイドロードを
    意識せずに利用できるインターフェースを提供する。
    """

    def __init__(self, local_node_id: str):
        self.node_id       = local_node_id

        # コンポーネント初期化
        self.registry      = NodeRegistry()
        self.hash_layer    = HashLayer()
        self.score_engine  = ScoreEngine(self.registry)
        self.sync_engine   = CRDTSyncEngine(local_node_id)
        self.backup_engine = BackupEngine(local_node_id)
        self.sideload_mgr  = SideloadManager(self.score_engine, self.registry)
        self.router        = EdgeRouter(self.registry, self.score_engine)

        self._request_count = 0

    # ---- 主要処理 ----

    def process_startup(self, nodes: List[Node]) -> None:
        """起動処理：ノード登録とレイテンシ初期計測"""
        for node in nodes:
            self.registry.process_register(node)
        self.registry.process_refresh_all_latencies()
        log.info(f"[API] Startup complete: {len(nodes)} nodes registered")

    def process_write(
        self, entry_id: str, data: str
    ) -> Dict[str, Any]:
        """
        データ書き込みAPI。
        中身のHashだけを管理し、実データは扱わない。
        """
        self._request_count += 1
        meta_hash = HashLayer.process_sha256(data)
        entry     = self.sync_engine.process_write(
            entry_id, meta_hash, len(data.encode())
        )

        # バックアップ判定
        wal_count = len(self.sync_engine.process_get_pending_wal())
        if self.backup_engine.branch_needs_snapshot(wal_count):
            self.backup_engine.process_snapshot(self.sync_engine._store)

        return {
            "entry_id":  entry.entry_id,
            "meta_hash": entry.meta_hash,
            "node_id":   entry.node_id,
            "status":    "written",
        }

    def process_sideload_request(
        self, package: Package
    ) -> Dict[str, Any]:
        """
        サイドロードリクエストAPI。
        最適ノードを選択し、スコア評価後にロード判定する。
        """
        node = self.router.process_select_best_node()
        if not node:
            return {
                "action": "REJECTED",
                "reason": "No available nodes",
                "score":  0.0,
            }
        return self.sideload_mgr.process_load(package, node.node_id)

    def process_sync_request(
        self, remote_entries: List[DataEntry]
    ) -> SyncResult:
        """同期リクエストAPI"""
        if self.sync_engine.branch_is_offline():
            return self.sync_engine.process_reconnect(remote_entries)
        return self.sync_engine.process_merge(remote_entries)

    def process_replicate_to(self, target_node_id: str) -> bool:
        """指定ノードへレプリケートするAPI"""
        return self.backup_engine.process_replicate(
            target_node_id, self.sync_engine._store
        )

    def process_get_root_hash(self) -> str:
        """現在のRootHashを取得するAPI"""
        _, root = self.sync_engine.process_build_local_merkle()
        return root

    def process_business_report(self, user_count: int) -> Dict[str, Any]:
        """ビジネス収支レポートを生成するAPI"""
        return self.score_engine.process_calc_business_score(user_count)

    # ---- 分岐処理 ----

    def branch_get_connection_mode(self) -> str:
        """現在の最適接続モードを取得"""
        return self.router.branch_select_connection_mode()

    def branch_is_root_synced(self, remote_root: str) -> bool:
        """RootがリモートのRootと同期済みかを判定"""
        local_root = self.process_get_root_hash()
        return HashLayer.branch_is_root_consistent(local_root, remote_root)

    def branch_needs_replication(self, target_node_id: str) -> bool:
        """レプリケーションが必要かを判定"""
        return self.backup_engine.branch_replica_is_stale(
            target_node_id, self.sync_engine._store
        )


# =============================================================================
# メイン処理：デモシナリオ
# =============================================================================

def _make_sample_nodes() -> List[Node]:
    """サンプルノードを生成する"""
    return [
        Node("local-01",  NodeTier.LOCAL,  "192.168.1.10", cost_per_unit=COST_PER_USER_LOCAL),
        Node("local-02",  NodeTier.LOCAL,  "192.168.1.11", cost_per_unit=COST_PER_USER_LOCAL),
        Node("edge-01",   NodeTier.EDGE,   "10.0.1.10",    cost_per_unit=COST_PER_USER_EDGE),
        Node("edge-02",   NodeTier.EDGE,   "10.0.2.10",    cost_per_unit=COST_PER_USER_EDGE),
        Node("center-01", NodeTier.CENTER, "203.0.113.10", cost_per_unit=COST_PER_USER_CENTER),
    ]


def _make_sample_package(name: str, trust: TrustLevel) -> Package:
    """サンプルパッケージを生成する"""
    pkg_id  = str(uuid.uuid4())
    version = "1.0.0"
    content = f"{name}-{version}-content"
    c_hash  = HashLayer.process_sha256(content)
    sig     = HashLayer.process_sha256(pkg_id + version + c_hash)
    return Package(
        package_id   = pkg_id,
        name         = name,
        version      = version,
        content_hash = c_hash,
        signature    = sig,
        trust_level  = trust,
        size_bytes   = random.randint(1024, 1_048_576),
        source_node  = "",
    )


def main():
    print("=" * 64)
    print(" 次世代エッジ分散アーキテクチャ - デモ実行")
    print("=" * 64)

    # ----------------------------------------
    # 1. システム起動
    # ----------------------------------------
    print("\n[1] システム起動")
    api   = EdgeArchAPI("local-01")
    nodes = _make_sample_nodes()
    api.process_startup(nodes)

    mode = api.branch_get_connection_mode()
    print(f"    接続モード: {mode}")

    # ----------------------------------------
    # 2. データ書き込みと整合性確認
    # ----------------------------------------
    print("\n[2] データ書き込み")
    sample_data = [
        ("doc-001", "重要なバックアップデータA"),
        ("doc-002", "設定ファイルB"),
        ("doc-003", "ユーザーメタデータC"),
    ]
    for eid, content in sample_data:
        result = api.process_write(eid, content)
        print(f"    {eid}: hash={result['meta_hash'][:16]}…")

    root = api.process_get_root_hash()
    print(f"    RootHash: {root[:20]}…")

    # ----------------------------------------
    # 3. サイドロード評価
    # ----------------------------------------
    print("\n[3] サイドロード評価")
    packages = [
        _make_sample_package("backup_agent_v2",   TrustLevel.HIGH),
        _make_sample_package("analytics_plugin",  TrustLevel.MEDIUM),
        _make_sample_package("kernel_module_hack", TrustLevel.LOW),
        _make_sample_package("config_sync_patch",  TrustLevel.HIGH),
    ]
    for pkg in packages:
        result = api.process_sideload_request(pkg)
        print(
            f"    [{result['action']:16}] {pkg.name:30} "
            f"score={result['score']:.3f}"
        )

    # ----------------------------------------
    # 4. オフライン→再接続シナリオ
    # ----------------------------------------
    print("\n[4] オフライン→再接続シナリオ")
    api.sync_engine.process_go_offline()
    print(f"    状態: {api.sync_engine.status.value}")

    # オフライン中に追加書き込み
    api.process_write("doc-offline-001", "オフライン中のデータ")
    wal = api.sync_engine.process_get_pending_wal()
    print(f"    WAL蓄積: {len(wal)} レコード")

    # 再接続（リモートエントリを模擬）
    remote_entries = [
        DataEntry(
            entry_id    = "doc-remote-001",
            meta_hash   = HashLayer.process_sha256("リモートで追加されたデータ"),
            size_bytes  = 512,
            updated_at  = time.time(),
            node_id     = "edge-01",
            vector_clock= {"edge-01": 5},
        )
    ]
    sync_result = api.sync_engine.process_reconnect(remote_entries)
    print(
        f"    同期結果: merged={sync_result.merged_count} "
        f"conflicts={sync_result.conflict_count} "
        f"status={sync_result.status.value}"
    )

    # ----------------------------------------
    # 5. Root整合性確認
    # ----------------------------------------
    print("\n[5] Root整合性確認")
    local_root  = api.process_get_root_hash()
    remote_root = local_root  # 同期後は一致するはず
    synced = api.branch_is_root_synced(remote_root)
    print(f"    ローカルRoot: {local_root[:20]}…")
    print(f"    Root整合性:   {'✓ 一致' if synced else '✗ 不一致'}")

    # ----------------------------------------
    # 6. レプリケーション
    # ----------------------------------------
    print("\n[6] バックアップ・レプリケーション")
    for target in ["edge-01", "center-01"]:
        if api.branch_needs_replication(target):
            success = api.process_replicate_to(target)
            print(f"    → {target}: {'✓ 完了' if success else '✗ 失敗'}")
        else:
            print(f"    → {target}: スキップ（最新状態）")

    snap = api.backup_engine.get_latest_snapshot()
    if snap:
        print(
            f"    最新スナップショット: "
            f"entries={snap['entry_count']} "
            f"root={snap['root_hash'][:16]}…"
        )

    # ----------------------------------------
    # 7. ビジネス収支レポート
    # ----------------------------------------
    print("\n[7] ビジネス収支レポート（月次試算）")
    header = f"{'ユーザー数':>12} {'広告収入':>14} {'CF収入':>14} {'インフラ':>14} {'利益':>14} {'利益率':>8}"
    print(f"    {header}")
    print("    " + "-" * 78)
    for count in [100_000, 500_000, 1_000_000, 5_000_000, 10_000_000]:
        r = api.process_business_report(count)
        print(
            f"    {r['user_count']:>12,} "
            f"¥{r['ad_revenue']:>13,} "
            f"¥{r['count_free_revenue']:>13,} "
            f"¥{r['infra_cost']:>13,} "
            f"¥{r['profit']:>13,} "
            f"{r['margin_pct']:>7.1f}%"
        )

    print("\n" + "=" * 64)
    print(" デモ完了")
    print("=" * 64)


if __name__ == "__main__":
    main()
