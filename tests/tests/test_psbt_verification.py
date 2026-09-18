from io import BytesIO

import pytest

from embit import ec, script
from embit.psbt import PSBT, PSBTError, CompressMode
from embit.psbtview import PSBTView
from embit.transaction import Transaction, TransactionInput, TransactionOutput


def funded_psbt(version):
    key = ec.PrivateKey((1).to_bytes(32, "big"))
    spk = script.p2wpkh(key.get_public_key())
    previous = Transaction(
        vin=[TransactionInput(bytes(32), 0)],
        vout=[TransactionOutput(10000, spk)],
    )
    psbt = PSBT(
        Transaction(
            vin=[TransactionInput(previous.txid(), 0)],
            vout=[TransactionOutput(9000, spk)],
        ),
        version=version,
    )
    psbt.inputs[0].non_witness_utxo = previous
    psbt.inputs[0].witness_utxo = TransactionOutput(10000, spk)
    return psbt, key


@pytest.mark.parametrize("version", [None, 2])
@pytest.mark.parametrize(
    "compress", [CompressMode.KEEP_ALL, CompressMode.CLEAR_ALL, CompressMode.PARTIAL]
)
@pytest.mark.parametrize("conflict", [None, "amount", "script"])
def test_verify_checks_both_utxo_representations(version, compress, conflict):
    psbt, key = funded_psbt(version)
    if conflict == "amount":
        psbt.inputs[0].witness_utxo.value = 1000
    elif conflict == "script":
        psbt.inputs[0].witness_utxo.script_pubkey = script.Script(b"\x51")
    raw = psbt.serialize()
    parsed = PSBT.parse(raw, compress=compress)
    viewed = PSBTView.view(BytesIO(raw), compress=compress).input(0)
    if conflict:
        for inp in (parsed.inputs[0], viewed):
            with pytest.raises(PSBTError, match="Witness utxo doesn't match"):
                inp.verify()
            assert not inp.is_verified
    else:
        assert parsed.verify()
        assert viewed.verify()
        assert parsed.fee() == 1000
        assert parsed.sign_with(key) == 1
        signature = parsed.inputs[0].partial_sigs[key.get_public_key()]
        assert key.verify(ec.Signature.parse(signature[:-1]), psbt.sighash(0))


def test_failed_reverification_clears_verified_state():
    psbt, _ = funded_psbt(None)
    inp = psbt.inputs[0]
    assert inp.verify()
    inp.witness_utxo.value = 1
    with pytest.raises(PSBTError):
        inp.verify()
    assert not inp.is_verified


@pytest.mark.parametrize("index", [-1, 1, None])
def test_verify_rejects_invalid_non_witness_output_index(index):
    psbt, _ = funded_psbt(None)
    psbt.inputs[0].vout = index
    with pytest.raises(PSBTError, match="output index"):
        psbt.verify()
    assert not psbt.is_verified
