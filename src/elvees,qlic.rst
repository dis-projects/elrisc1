=========================
QLIC Interrupt controller
=========================

Properties:

- compatible:
	Usage: required
	Value type: <string>
	Definition: Should be "elvees,qlic"

- reg:
	Usage: required
	Value type: <prop-encoded-array>
	Definition: Specifies the base physical address for hardware.

- targets:
	Usage: required
	Value type: <prop-encoded-array>
	Definition: Specifies QLIC targets to parent interrupt controller. Each
	target corresponds to an interrupt in "interrupt" property.


- interrupt-cells:
	Usage: required
	Value type: <u32>
	Definition: Specifies the number of cells needed to encode an interrupt
		    source.
		    Must be 1.
		    The first element is the QLIC pin for the interrupt.

- interrupt-controller:
	Usage: required
	Value type: <bool>
	Definition: Identifies the node as an interrupt controller.

- interrupts:
	Usage: required
	Value type: <prop-encoded-array>
	Definition: Specifies the interrupts to parent interrupt controller.

Example:

Here pin-ranges in the interrupt-controller node indicates:

* 16 QLIC target -> 11 GIC.
* 17 QLIC target -> 12 GIC.

Following interrupts are configured for elcore0 node:

* 17 QLIC interrupt -> 16 QLIC target -> 11 GIC SPI.
* 18 QLIC interrupt -> 17 QLIC target -> 12 GIC SPI.
* 19 QLIC interrupt -> 16 QLIC target -> 11 GIC SPI.
* 20 QLIC interrupt -> 17 QLIC target -> 12 GIC SPI.

qlic0_intc: interrupt-controller@1940000 {
	compatible = "elvees,qlic";
	interrupt-controller;
	targets = <16>, <17>;
	#interrupt-cells = <1>;
	interrupt-parent = <&gic>;
	interrupts = <GIC_SPI 11 IRQ_TYPE_LEVEL_HIGH>,
		     <GIC_SPI 12 IRQ_TYPE_LEVEL_HIGH>;
	reg = <0x1940000 0x40000>;
	status = "disabled";
};

elcore0: elcore@1980000 {
	compatible = "elvees,elcore50";
	reg = <0x1980000 0x40000>,
	      <0x3000000 0x200000>;
	interrupt-parent = <&qlic0_intc>;
	interrupts = <16>, <17>, <18>,
		     <19>, <20>;
};
