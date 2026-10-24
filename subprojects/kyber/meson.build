project('kyber', 'c',
  license: 'CC0-1.0 OR Apache-2.0',
  default_options: ['optimization=2', 'warning_level=0'],
)

# pq-crystals Kyber, round-3 reference (SHAKE variant), built as Kyber-1024 only.
# Apple's NGM registration prekey KEM is round-3 Kyber-1024 (not FIPS ML-KEM-1024),
# so Idun needs this exact variant to interoperate.
kyber_sources = files(
  'kem.c',
  'indcpa.c',
  'polyvec.c',
  'poly.c',
  'ntt.c',
  'cbd.c',
  'reduce.c',
  'verify.c',
  'fips202.c',
  'symmetric-shake.c',
  'randombytes.c',
)

kyber_lib = static_library('pqcrystals_kyber1024_ref', kyber_sources,
  c_args: ['-DKYBER_K=4'],
  pic: true,
)

kyber_dep = declare_dependency(
  link_with: kyber_lib,
  include_directories: include_directories('.'),
)

meson.override_dependency('kyber', kyber_dep)
