import java.security.PublicKey;
import java.util.*;

public class TxHandler {

    private UTXOPool utxoPool;
    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
    	List<Transaction.Input> inputs = tx.getInputs();
    	List<Transaction.Output> outputs = tx.getOutputs();

        // ------- 1: all outputs are in current UTXO pool      //DONE
        for(int i = 0; i < tx.numInputs(); i++){
            UTXO utxo = new UTXO(inputs.get(i).prevTxHash, inputs.get(i).outputIndex);
            if(!utxoPool.contains(utxo)){
                return false;
            }
        }

        // ------- 2: all signatures on each input are valid
        for(int i = 0; i < tx.numInputs(); i++){
        	UTXO utxo = new UTXO(inputs.get(i).prevTxHash, inputs.get(i).outputIndex);
            PublicKey publicKey = utxoPool.getTxOutput(utxo).address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = inputs.get(i).signature;

            if(!Crypto.verifySignature(publicKey, message, signature) ){
                return false;
            }
        }

        // ------- 3: no UTXO is claimed multiple times     //DONE
        ArrayList<UTXO> listOfUTXO = new ArrayList<>();
        for(int i = 0; i < tx.numInputs(); i++){
            UTXO utxo = new UTXO(inputs.get(i).prevTxHash, inputs.get(i).outputIndex);
            if(listOfUTXO.contains(utxo)){
                return false;
            }
            listOfUTXO.add(utxo);
        }

        // ------- 4: All output values are non-negative        //DONE
        for(int i = 0; i < tx.numOutputs(); i++){
            if(outputs.get(i).value < 0){
                return false;
            }
        }

        // ------- 5: The sum of output values inputs are greater than or equal to the sum of its outputs
        double sumInputs = 0;
        double sumOutputs = 0;

        for(int i = 0; i < tx.numOutputs(); i++){
            sumOutputs += outputs.get(i).value;
        }

        for(int i = 0; i < tx.numInputs(); i++){
            UTXO utxo = new UTXO(inputs.get(i).prevTxHash, inputs.get(i).outputIndex);
            sumInputs += utxoPool.getTxOutput(utxo).value;
        }

        return sumOutputs < sumInputs;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> transactions = new ArrayList<Transaction>();

        for(int i = 0; i < possibleTxs.length; i++){
            if(isValidTx(possibleTxs[i])){                      //Check for correctness
                Transaction validTransaction = possibleTxs[i];
                transactions.add(validTransaction);

                for(int j = 0; j < validTransaction.numInputs(); j++){          //Remove the current outputs from UTXO
                    UTXO utxo = new UTXO(validTransaction.getInput(j).prevTxHash, validTransaction.getInput(j).outputIndex);
                    utxoPool.removeUTXO(utxo);
                }

                for(int j = 0; j < validTransaction.numOutputs(); j++){         //Add new outputs to UTXO
                    UTXO utxo = new UTXO(validTransaction.getHash(), j);
                    utxoPool.addUTXO(utxo, validTransaction.getOutput(j));
                }

            }
        }

        Transaction[] finalTransactions = new Transaction[transactions.size()];
        finalTransactions = transactions.toArray(finalTransactions);
        return finalTransactions;               // Return valid array of accepted transactions
    }

}
