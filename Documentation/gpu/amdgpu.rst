=========================
 drm/amdgpu AMDgpu driver
=========================

The drm/amdgpu driver supports all AMD Radeon GPUs based on the Graphics Core
Next (GCN) architecture.

Core Driver Infrastructure
==========================

This section covers core driver infrastructure.

PRIME Buffer Sharing
--------------------

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_prime.c
   :doc: PRIME Buffer Sharing

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_prime.c
   :internal:

MMU Notifier
------------

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_mn.c
   :doc: MMU Notifier

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_mn.c
   :internal:

AMDGPU Virtual Memory
---------------------

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c
   :doc: GPUVM

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c

Interrupt Handling
------------------

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_irq.c
   :doc: Interrupt Handling

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_irq.c
   :internal:

GPU Power/Thermal Controls and Monitoring
=========================================

This section covers hwmon and power/thermal controls.

HWMON Interfaces
----------------

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: hwmon

GPU sysfs Power State Interfaces
--------------------------------

GPU power controls are exposed via sysfs files.

power_dpm_state
~~~~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: power_dpm_state

power_dpm_force_performance_level
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: power_dpm_force_performance_level

pp_table
~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: pp_table

pp_od_clk_voltage
~~~~~~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: pp_od_clk_voltage

pp_dpm_sclk pp_dpm_mclk pp_dpm_pcie
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: pp_dpm_sclk pp_dpm_mclk pp_dpm_pcie

pp_power_profile_mode
~~~~~~~~~~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: pp_power_profile_mode

busy_percent
~~~~~~~~~~~~

.. kernel-doc:: drivers/gpu/drm/amd/amdgpu/amdgpu_pm.c
   :doc: busy_percent
