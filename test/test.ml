open Tweetnacl
open Bip32_ed25519

let gen_key () =
  let rec inner i =
    try i, of_seed (Rand.gen 32) with _ -> inner (succ i)
  in inner 0

let basic () =
  let i, sk = gen_key () in
  let pk = neuterize sk in
  let sk' = derive sk 0l in
  let pk' = derive pk 0l in
  let pk'' = neuterize sk' in
  Format.printf "\n%a\n%a\n" pp pk' pp pk'';
  assert (equal pk' pk'')

let basic = [
  "basic", `Quick, basic ;
]

let () =
  Alcotest.run "Bip32_ed25519" [
    "basic", basic ;
  ]
