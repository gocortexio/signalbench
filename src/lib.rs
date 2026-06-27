// SPDX-FileCopyrightText: GoCortexIO
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Library facade.
//!
//! The signalbench binary (`src/main.rs`) does not depend on this file --
//! it declares its own private module tree.  This `lib.rs` exists solely
//! so integration tests under `tests/` can reach the same modules with
//! `use signalbench::...`.  Modules listed here are the audited public
//! surface; everything else stays internal.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::question_mark)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::collapsible_if)]

pub mod chain;
pub mod cli;
pub mod config;
pub mod easter_egg;
pub mod logger;
pub mod runner;
pub mod safety;
pub mod suites;
pub mod techniques;
pub mod utils;
pub mod voltron;
