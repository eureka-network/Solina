# Solina

An intent-solver framework, for customized problem-specific computing solutions.

## Architecture

1. Given a well specified computing problem, like trading on a (or multiple) DEXes with many economic agents, users express their `Intent`, that is, their desired outcome given the user inputs satisfying precise (boundary) constraints.

2. Intents are aggregated in batches, and each batch is processed via multiple `Solver`'s. A Solver is an entity, with enough available compute power, that produces a solution specific to the processed batch. 

3. Solutions presented by `Solver`'s should, ideally, satisfy the biggest number of participants, by a well defined metric (which is context dependent).

4. Given such a metric, users satisfaction over a solution can be quantified, which allows to choose the best solution among all proposed `Solver`'s solutions. The best available solution(s) then accrues fues to Solvers. 

5. In this way, we allow for a market between user `Intent`s and `Solver`s compute power. 

## Example

As previously mentioned, consider the case in which multiple market 
participants express their trade `Intent` (for example, Alice expresses the 
intent of swaping `X` tokens `A` by at least an amount `Y` of tokens B, at 
a current fixed price). 

These trading `Intent`s are aggregated into a batch of `N`, with a
fixed price (possibly, the average price, over multiple oracles, at the given time of execution). 

A `Solver` provides a possible solution to the 
current problem (possibly, by matching Alice's trade with Bob's, in which
the aggregate satisfies all the constraints).

Given the proposed solution, users express their satisfaction, if their intent has been processed and the solution with highest number of processed trades is chosen. 

The `Solver` who proposed this solution accrues the fees, and the trades
are performed (say, on a DEX, or multiple DEXes).

## Cryptographic guarantees

To automize the described process, we propose the use of Zero Knowledge cryptography to testify to the following requirements:

1. `Intent`s are signed by users, so they can be claimed. We use ECDSA
signatures of Ethereum's EIP-712 structured hash of the `Intent` contents,
full compatible with Ethereum's signature scheme.

2. `Intent` constraints are satisfied by each proposed solution. This reflects the integrity of each `Solver`'s solution.

## Related work

We present a, possibly non-exhaustive, list of related projects, which we
derived inspiration from:

1. Cow swap intent based trade platform:

https://docs.cow.fi/overview/introduction

2. Anoma's intent centric protocol:

https://anoma.net/
