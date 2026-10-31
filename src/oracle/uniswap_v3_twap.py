from __future__ import annotations
import time
from dataclasses import dataclass, field
from decimal import Decimal
@dataclass
class Observation:
    timestamp: int; tick_cumulative: int; block_number: int; liquidity: int; initialized: bool = True
@dataclass
class Pool:
    address: str; token0: str; token1: str; observations: list[Observation] = field(default_factory=list); observation_index: int = 0; observation_cardinality: int = 0; observation_cardinality_next: int = 2; min_observation_duration: int = 300
class UniswapV3TWAPOracle:
    def __init__(self, min_observation_duration=300): self.pools, self.min_observation_duration, self.max_twap_window = {}, min_observation_duration, 3600
    def add_pool(self, pool_address, token0, token1):
        if pool_address not in self.pools: self.pools[pool_address] = Pool(pool_address, token0, token1, min_observation_duration=self.min_observation_duration)
    def record_observation(self, pool_address, tick_cumulative, block_number, liquidity, timestamp=None):
        pool = self.pools.get(pool_address)
        if pool is None: raise ValueError(f'Pool {pool_address} not found')
        pool.observations.append(Observation(int(time.time()) if timestamp is None else timestamp, tick_cumulative, block_number, liquidity)); pool.observation_cardinality = len(pool.observations); pool.observation_index = pool.observation_cardinality - 1
    def consult(self, pool_address, window, now=None):
        pool = self.pools.get(pool_address)
        if pool is None: raise ValueError(f'Pool {pool_address} not found')
        if window < pool.min_observation_duration or window > self.max_twap_window: raise ValueError('TWAP window is outside the permitted range')
        current = int(time.time()) if now is None else now; eligible = [o for o in pool.observations if o.initialized and 0 <= current-o.timestamp <= window]
        if len(eligible) < 2: raise ValueError('insufficient observations for TWAP')
        start, end = eligible[0], eligible[-1]; duration = end.timestamp - start.timestamp
        if duration < pool.min_observation_duration: raise ValueError('observation duration is too short')
        return Decimal('1.0001') ** (Decimal(end.tick_cumulative - start.tick_cumulative) / Decimal(duration))
