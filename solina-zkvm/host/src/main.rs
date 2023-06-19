use risc0_zkvm::{
    serde::{from_slice, to_vec},
    Executor, ExecutorEnv,
};
use solina_zkvm_methods::{SOLINA_ZKVM_METHODS_ELF, SOLINA_ZKVM_METHODS_ID};

fn main() {
    // First, we construct an executor environment
    let env = ExecutorEnv::builder().build();

    // TODO: add guest input to the executor environment using
    // ExecutorEnvBuilder::add_input().
    // To access this method, you'll need to use the alternate construction
    // ExecutorEnv::builder(), which creates an ExecutorEnvBuilder. When you're
    // done adding input, call ExecutorEnvBuilder::build().

    // For example: let env = ExecutorEnv::builder().add_input(&vec).build();

    // Next, we make an executor, loading the (renamed) ELF binary.
    let mut exec = Executor::from_elf(env, SOLINA_ZKVM_METHODS_ELF).unwrap();

    // Run the executor to produce a session.
    let session = exec.run().unwrap();

    // Prove the session to produce a receipt.
    let receipt = session.prove().unwrap();

    // TODO: Implement code for transmitting or serializing the receipt for
    // other parties to verify here

    // Optional: Verify receipt to confirm that recipients will also be able to
    // verify your receipt
    receipt.verify(SOLINA_ZKVM_METHODS_ID).unwrap();
}
