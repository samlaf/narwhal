# Copyright(C) Facebook, Inc. and its affiliates.
from os.path import join

from benchmark.utils import PathMaker


class CommandMaker:

    @staticmethod
    def cleanup():
        return (
            f'rm -r .db-* ; rm .*.json ; mkdir -p {PathMaker.results_path()}'
        )

    @staticmethod
    def clean_logs():
        return f'rm -r {PathMaker.logs_path()} ; mkdir -p {PathMaker.logs_path()}'

    @staticmethod
    def compile():
        return 'cargo build --quiet --release --features benchmark'

    @staticmethod
    def generate_key(filename):
        assert isinstance(filename, str)
        return f'./node generate_keypair --filename {filename}'

    @staticmethod
    def generate_threshold_keypair(filename, threshold, node_index, seed):
        assert isinstance(filename, str)
        assert isinstance(threshold, int)
        assert isinstance(node_index, int)
        assert isinstance(seed, int)
        return (f'./node generate_threshold_keypair --filename {filename} '
                f'--seed {seed} --threshold {threshold} --node_index {node_index}')

    @staticmethod
    def generate_threshold_publickey(filename, threshold, seed):
        assert isinstance(filename, str)
        assert isinstance(threshold, int)
        assert isinstance(seed, int)
        return (f'./node generate_threshold_publickey --filename {filename} '
                f'--seed {seed} --threshold {threshold}')

    @staticmethod
    def run_primary(keys, committee, store, parameters, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keypair {keys} --committee {committee} '
                f'--store {store} --parameters {parameters} primary')

    @staticmethod
    def run_worker(keys, threshold_keypair, committee, store, parameters, id, debug=False):
        assert isinstance(keys, str)
        assert isinstance(committee, str)
        assert isinstance(parameters, str)
        assert isinstance(debug, bool)
        v = '-vvv' if debug else '-vv'
        return (f'./node {v} run --keypair {keys} --committee {committee} --store {store} '
                f'--parameters {parameters} worker --id {id} --threshold_keypair {threshold_keypair}')

    @staticmethod
    def run_client(address, threshold_pk_filename, size, rate, nodes):
        assert isinstance(address, str)
        assert isinstance(threshold_pk_filename, str)
        assert isinstance(size, int) and size > 0
        assert isinstance(rate, int) and rate >= 0
        assert isinstance(nodes, list)
        assert all(isinstance(x, str) for x in nodes)
        nodes = f'--nodes {" ".join(nodes)}' if nodes else ''
        return f'./benchmark_client {address} --threshold_pk {threshold_pk_filename} --size {size} --rate {rate} --nodes {nodes}'

    @staticmethod
    def kill():
        return 'tmux kill-server'

    @staticmethod
    def alias_binaries(origin):
        assert isinstance(origin, str)
        node, client = join(origin, 'node'), join(origin, 'benchmark_client')
        return f'rm node ; rm benchmark_client ; ln -s {node} . ; ln -s {client} .'
