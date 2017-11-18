/*
 * SpiceWire module for ARM architecture.
 *
 * Copyright (c) 2017 Lukasz Wlazly.
 * Written as a part of BSc thesis
 *
 * This code is licensed under the GPL.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/error-report.h"

#define TYPE_SPACEWIRE "spacewire"
#define SPACEWIRE(obj) OBJECT_CHECK(SpaceWireState, (obj), TYPE_SPACEWIRE)

typedef struct SpaceWireState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    int level[2];
    qemu_irq irq;
} SpaceWireState;

static uint64_t fake_val;

static uint64_t space_wire_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    error_report("read");
    return fake_val;
}

static void space_wire_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    error_report("write");
    fake_val = value + 32;
}

static const MemoryRegionOps space_wire_ops = {
    .read = space_wire_read,
    .write = space_wire_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static const VMStateDescription vmstate_space_wire = {
    .name = "spacewire",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_INT32_ARRAY(level, SpaceWireState, 2),
        VMSTATE_END_OF_LIST()
    }
};

static void space_wire_init(Object *obj)
{
    SpaceWireState *s = SPACEWIRE(obj);
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);

    sysbus_init_irq(sbd, &s->irq);
    memory_region_init_io(&s->iomem, obj, &space_wire_ops, s,
                          "spacewire", 0x1000);
    sysbus_init_mmio(sbd, &s->iomem);
}

static void space_wire_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *k = DEVICE_CLASS(klass);
    k->vmsd = &vmstate_space_wire;
}

static const TypeInfo space_wire_info = {
    .name          = TYPE_SPACEWIRE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(SpaceWireState),
    .instance_init = space_wire_init,
    .class_init    = space_wire_class_init,
};

static void spacewire_register_types(void)
{
    type_register_static(&space_wire_info);
}

type_init(spacewire_register_types)
