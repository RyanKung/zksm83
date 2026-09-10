//! Shared Halo2 expressions for fixed shape selectors and byte/word values.

use halo2_proofs::{
    plonk::{Advice, Column, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use pasta_curves::Fp;

use crate::{bus::BusConfig, shape::ShapeConfig};

pub(crate) const ROLE_OPCODE_ZERO: usize = 1;
pub(crate) const ROLE_OPCODE_ONE: usize = 2;
pub(crate) const ROLE_IMMEDIATE_ZERO: usize = 3;
pub(crate) const ROLE_IMMEDIATE_ONE: usize = 4;
pub(crate) const ROLE_DATA_ZERO: usize = 5;
pub(crate) const ROLE_DATA_ONE: usize = 6;

pub(crate) fn operation(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    code: usize,
) -> Expression<Fp> {
    fixed(meta, &shape.operation, code)
}

pub(crate) fn argument_zero(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    code: usize,
) -> Expression<Fp> {
    fixed(meta, &shape.argument_zero, code)
}

pub(crate) fn argument_one(
    meta: &mut VirtualCells<'_, Fp>,
    shape: &ShapeConfig,
    code: usize,
) -> Expression<Fp> {
    fixed(meta, &shape.argument_one, code)
}

pub(crate) fn event_value(
    meta: &mut VirtualCells<'_, Fp>,
    bus: &BusConfig,
    shape: &ShapeConfig,
    role: usize,
) -> Expression<Fp> {
    selected_event(meta, bus, shape, role, |event| event.value)
}

pub(crate) fn event_address(
    meta: &mut VirtualCells<'_, Fp>,
    bus: &BusConfig,
    shape: &ShapeConfig,
    role: usize,
) -> Expression<Fp> {
    selected_event(meta, bus, shape, role, |event| event.address)
}

pub(crate) fn word(low: Expression<Fp>, high: Expression<Fp>) -> Expression<Fp> {
    low + Expression::Constant(Fp::from(256)) * high
}

fn fixed<const N: usize>(
    meta: &mut VirtualCells<'_, Fp>,
    columns: &[Column<Fixed>; N],
    index: usize,
) -> Expression<Fp> {
    columns
        .get(index)
        .map_or(Expression::Constant(Fp::zero()), |column| {
            meta.query_fixed(*column)
        })
}

fn selected_event(
    meta: &mut VirtualCells<'_, Fp>,
    bus: &BusConfig,
    shape: &ShapeConfig,
    role: usize,
    column: impl Fn(crate::bus::EventColumns) -> Column<Advice>,
) -> Expression<Fp> {
    bus.events.iter().zip(&shape.event_roles).fold(
        Expression::Constant(Fp::zero()),
        |sum, (event, roles)| {
            sum + fixed(meta, roles, role) * meta.query_advice(column(*event), Rotation::cur())
        },
    )
}
