#![feature(associated_type_bounds)]
#![cfg_attr(coverage_nightly, feature(no_coverage))]

pub extern crate shamir_ss;
pub extern crate sigmazk;
pub mod selfcompiler;
pub mod shareable;
#[cfg(test)]
mod tests;

use itertools::Itertools;
use rand_core::CryptoRngCore;
use shamir_ss::shamir::{ShamirSecretSharing, Share};
use shareable::Shareable;
use sigmazk::message::Message;
use sigmazk::{HVzk, Schnorr, SigmaProtocol};
use std::fmt::{self, Debug};

pub trait Composable:
    SigmaProtocol<
        MessageA: Message,
        Challenge: Shareable + Message,
        MessageZ: Message,
    > + HVzk
    + Clone
    + Debug
    + Default
{
}

impl Composable for Schnorr {}
