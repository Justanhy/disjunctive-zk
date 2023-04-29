// use proc_macro::TokenStream;
// use proc_macro2::{Ident, TokenStream as TokenStream2};
// use quote::{format_ident, quote, quote_spanned, ToTokens};
// use std::fmt::Debug;
// use std::str::FromStr;
// use syn::parse::{Parse, ParseStream};
// use syn::punctuated::Punctuated;
// use syn::{parse2, Expr, Lit, Result, Token};

// #[proc_macro]
// /// Macro to generate the appropriate SelfStacker type
// /// needed for a given number of clauses and a sigma
// /// protocol that is stackable.
// ///
// /// # Parameters
// /// 1. Number of clauses
// /// 2. Sigma protocol to stack
// /// 3. (Optional) name of the SelfStacker type; by default
// /// this is `StackedSigma`
// ///
// /// # Example
// /// ```rust
// /// selfstack!(100, Schnorr)
// /// ```
// /// expands to
// /// ```rust
// ///     type S2 = SelfStacker<Schnorr>;
// ///     type S4 = SelfStacker<S2>;
// ///     type S8 = SelfStacker<S4>;
// ///     type S16 = SelfStacker<S8>;
// ///     type S32 = SelfStacker<S16>;
// ///     type S64 = SelfStacker<S32>;
// ///     type StackedSigma = SelfStacker<S64>;
// /// ```
// pub fn selfstack(input: TokenStream) -> TokenStream {
//     let tokens = TokenStream2::from(input);
//     impl_selfstack(tokens).into()
// }

// struct Parameters {
//     pub params: Punctuated<Expr, Token![,]>,
// }

// impl Debug for Parameters {
//     fn fmt(
//         &self,
//         f: &mut std::fmt::Formatter<'_>,
//     ) -> std::fmt::Result {
//         let out = self
//             .params
//             .clone()
//             .into_pairs()
//             .fold(Vec::new(), |mut acc, pair| {
//                 let (token, _) = pair.into_tuple();
//                 acc.push(token.to_token_stream());
//                 acc
//             });
//         f.debug_struct("Parameters")
//             .field("params", &out)
//             .finish()
//     }
// }

// impl Parse for Parameters {
//     fn parse(input: ParseStream) -> Result<Self> {
//         Ok(Self {
//             params: input.parse_terminated(Expr::parse)?,
//         })
//     }
// }

// fn impl_selfstack(input: TokenStream2) -> TokenStream2 {
//     let params: Parameters = parse2(input).unwrap();
//     let params: Vec<Expr> = params
//         .params
//         .into_pairs()
//         .map(|pair| {
//             let (token, _) = pair.into_tuple();
//             token
//         })
//         .collect();

//     if params.len() < 2 || params.len() > 3 {
//         panic!("Expected 2 non-optional parameters");
//     }

//     let clauses = match &params[0] {
//         Expr::Lit(expr) => match &expr.lit {
//             Lit::Int(lit) => {
//                 let n = lit
//                     .base10_parse::<usize>()
//                     .unwrap();
//                 n
//             }
//             _ => panic!("Expected integer"),
//         },
//         _ => panic!("Expected integer literal"),
//     };

//     let height = clauses.ilog2();

//     let sigma: Ident = parse2(
//         params[1]
//             .clone()
//             .to_token_stream(),
//     )
//     .unwrap();

//     let sigma_span = sigma.span();

//     let assert_stackable = quote_spanned! {sigma_span=>
//         struct _AssertStackable where #sigma: Stackable;
//     };

//     let final_type: Ident = if params.len() == 3 {
//         parse2(
//             params[2]
//                 .clone()
//                 .to_token_stream(),
//         )
//         .unwrap()
//     } else {
//         parse2(
//             TokenStream2::from_str("StackedSigma").unwrap(),
//         )
//         .unwrap()
//     };

//     let types = (0..height).map(|i| {
//         let name =
//             format_ident!("S{}", (1 << (i + 1)) as usize);
//         if i == 0 {
//             quote! {
//                 type #name = SelfStacker<#sigma>;
//             }
//         } else {
//             let before =
//                 format_ident!("S{}", (1 << i) as usize);
//             if i == height - 1 {
//                 quote! {
//                     type #final_type = SelfStacker<#before>;
//                 }
//             } else {
//                 quote! {
//                     type #name = SelfStacker<#before>;
//                 }
//             }
//         }
//     });

//     let gen = quote! {
//         #assert_stackable
//         #( #types )*
//     };
//     gen.into()
// }

// // #[cfg(test)]
// // mod tests {
// //     use std::str::FromStr;

// //     use super::*;

// //     #[test]
// //     fn impl_selfstack_works() {
// //         let tokens =
// //             TokenStream2::from_str("100235, Schnorr")
// //                 .unwrap();
// //         let gen = impl_selfstack(tokens);
// //         println!("{}", gen);
// //     }
// // }
