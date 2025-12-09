use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Index, LitInt, Result};

pub fn evaluate(input: LitInt) -> Result<TokenStream> {
    let max_tuple_size = input.base10_parse::<usize>()?;
    if max_tuple_size < 2 {
        return Err(syn::Error::new_spanned(
            input,
            "max tuple size must be at least 2",
        ));
    }

    let impls = (2..max_tuple_size).map(generate_impl_for_size);

    Ok(quote! {
        #(#impls)*
    })
}

/// Generate a single MaybeCast implementation for a tuple of the given size.
fn generate_impl_for_size(size: usize) -> TokenStream {
    let mut generics = quote! {};
    let mut tuple_types = quote! {};
    let mut output_types = quote! {};
    let mut empty_values = quote! {};
    let mut cast_values = quote! {};

    for i in 0..size {
        let ty = format_ident!("T{}", i);
        let idx = Index::from(i);

        generics.extend(quote! { #ty: Send, });
        tuple_types.extend(quote! { #ty, });
        output_types.extend(quote! { K::Rebind<#ty>, });
        empty_values.extend(quote! { K::empty(), });
        cast_values.extend(quote! { K::maybe_just(|| self.#idx), });
    }

    quote! {
        impl<#generics K: MaybeKind> MaybeCast<(#tuple_types), K> for (#tuple_types) {
            type Output = (#output_types);

            fn empty() -> Self::Output {
                (#empty_values)
            }

            fn cast(self) -> Self::Output {
                (#cast_values)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;
    use syn::parse_quote;

    #[test]
    fn test_generate_2tuple() {
        let output = generate_impl_for_size(2);
        let expected = quote! {
            impl<T0: Send, T1: Send, K: MaybeKind> MaybeCast<(T0, T1,), K> for (T0, T1,) {
                type Output = (K::Rebind<T0>, K::Rebind<T1>,);

                fn empty() -> Self::Output {
                    (K::empty(), K::empty(),)
                }

                fn cast(self) -> Self::Output {
                    (K::maybe_just(|| self.0), K::maybe_just(|| self.1),)
                }
            }
        };
        assert_eq!(output.to_string(), expected.to_string());
    }

    #[test]
    fn test_evaluate() {
        // Test with 4 to generate implementations for sizes 2 and 3 (exclusive upper bound)
        let input: syn::LitInt = parse_quote!(4);
        let output = evaluate(input).unwrap();
        assert!(!output.is_empty());

        // Verify it contains impl for 2-tuple and 3-tuple, but not 4-tuple
        let output_str = output.to_string();
        assert!(output_str.contains("T0"));
        assert!(output_str.contains("T1"));
        assert!(output_str.contains("T2"));
        assert!(!output_str.contains("T3"));
    }

    #[test]
    fn test_evaluate_minimum() {
        // Test minimum valid input (2 generates nothing, since range is 2..2)
        let input: syn::LitInt = parse_quote!(2);
        let output = evaluate(input).unwrap();
        assert_eq!(output.to_string(), "");
    }

    #[test]
    fn test_evaluate_error() {
        // Test that values less than 2 produce an error
        let input: syn::LitInt = parse_quote!(1);
        assert!(evaluate(input).is_err());
    }
}
