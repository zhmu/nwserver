use proc_macro::TokenStream;
use quote::quote;

use syn::{parse_macro_input, DeriveInput, Error};
use syn::spanned::Spanned;

enum Type {
    U8,
    U16,
    U32,
    MaxBoundedString,
    NcpFileHandle,
}

struct Field {
    name: String,
    typ: Type,
}

struct NcpPacket {
    name: String,
    descr: String,
    fields: Vec<Field>
}

fn type_to_string(ty: &syn::Type) -> String {
    let ty = quote!(#ty).to_string();
    ty
}

fn parse_type(ty: &syn::Type) -> Option<Type> {
    return match type_to_string(ty).as_str() {
        "u8" => Some(Type::U8),
        "u16" => Some(Type::U16),
        "u32" => Some(Type::U32),
        "MaxBoundedString" => Some(Type::MaxBoundedString),
        "NcpFileHandle" => Some(Type::NcpFileHandle),
        _ => { None }
    }
}

fn generate_read_for_type(ty: &Type, rdr: &str) -> String {
    match ty {
        Type::U8 => { format!("{rdr}.read_u8()?", rdr=rdr) },
        Type::U16 => { format!("{rdr}.read_u16::<BigEndian>()?", rdr=rdr) },
        Type::U32 => { format!("{rdr}.read_u32::<BigEndian>()?", rdr=rdr) },
        Type::MaxBoundedString => { format!("MaxBoundedString::from({rdr})?", rdr=rdr) },
        Type::NcpFileHandle => { format!("NcpFileHandle::from({rdr})?", rdr=rdr) },
    }
}

fn parse_packet(s: &syn::DataStruct, name: &str) -> Result<NcpPacket, Error> {
    let mut fields: Vec<Field> = Vec::new();
    let mut descr: String = format!("{}", name);
    for field in &s.fields {
        let name = match &field.ident {
            Some(name) => name.to_string(),
            _ => { return Err(Error::new(field.span(), "all fields must be named")) }
        };
        let typ = match parse_type(&field.ty) {
            Some(ty) => ty,
            None => {
                return Err(Error::new(field.ty.span(), format!("unsupported type {}", type_to_string(&field.ty))))
            }
        };
        for attr in &field.attrs {
            let node = attr.parse_meta()?;
            match node {
                syn::Meta::NameValue(ref name_value) => {
                    if let Some(ident) = name_value.path.get_ident() {
                        if ident == "descr" {
                            if let syn::Lit::Str(ref s) = name_value.lit {
                                descr = s.value();
                            } else {
                                return Err(Error::new(name_value.path.span(), "#[descr] takes a string as argument"));
                            }
                        }
                    }
                },
                _ => {
                    return Err(Error::new(node.span(), "unsupported meta attribute"))
                }
            }
        }
        fields.push(Field{ name, typ })
    }
    Ok(NcpPacket{ name: name.to_string(), descr, fields })
}

fn generate_read_fields(ncp_packet: &NcpPacket) -> Result<String, Error> {
    let mut statements: String = String::new();
    for f in &ncp_packet.fields {
        let s = format!("
            let {name} = {read};
        ", name = f.name, read = generate_read_for_type(&f.typ, "rdr"));
        statements += &s;
    }
    Ok(statements)
}

fn generate_field_names(ncp_packet: &NcpPacket) -> Result<String, Error> {
    let mut s: String = String::new();
    for f in &ncp_packet.fields {
        if !s.is_empty() { s += ", "; }
        s += &f.name;
    }
    Ok(s)
}

fn generate_from_impl(ncp_packet: &NcpPacket) -> Result<proc_macro2::TokenStream, Error> {
    let read_fields = generate_read_fields(&ncp_packet)?;
    let field_names = generate_field_names(&ncp_packet)?;
    let impls = format!("
        impl {name} {{
            pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {{
                {read_fields}
                Ok(Self{{ {field_names} }})
            }}
        }}
    ", name=ncp_packet.name, read_fields=read_fields, field_names=field_names);
    let stmt: syn::Stmt = syn::parse_str(&impls).expect("generate_from_impl failed");
    Ok(quote! { #stmt })
}

fn generate_print_impl(ncp_packet: &NcpPacket) -> Result<proc_macro2::TokenStream, Error> {
    let mut fmt_str = String::new();
    let mut fmt_fields = String::new();
    for f in &ncp_packet.fields {
        fmt_str += format!("{}: {{}} ", f.name).as_str();
        fmt_fields += format!(", self.{}", f.name).as_str();
    }

    let display_impl = format!("
        impl fmt::Display for {name} {{
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {{
                write!(fmt, \"{descr} {{{{ {fmt_str} }}}}\" {fmt_fields})
            }}
        }}
    ", name=ncp_packet.name, fmt_str=fmt_str, fmt_fields=fmt_fields, descr=ncp_packet.descr);
    let display: syn::Stmt = syn::parse_str(&display_impl).expect("generate_print_impl failed");

    let debug_impl = format!("
        impl fmt::Debug for {name} {{
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {{
                fmt::Display::fmt(self, fmt)
            }}
        }}
    ", name=ncp_packet.name);
    let debug: syn::Stmt = syn::parse_str(&debug_impl).expect("generate_print_impl failed");
    Ok(quote! { #display #debug })
}

fn generate_ncp_packet(s: &syn::DataStruct, name: String) -> Result<proc_macro2::TokenStream, Error> {
    let ncp_packet = parse_packet(s, &name)?;

    let from_impl = generate_from_impl(&ncp_packet)?;
    let print_impl = generate_print_impl(&ncp_packet)?;
    let ts = quote! { #from_impl #print_impl };
    Ok(ts)
}

#[proc_macro_derive(NcpPacket,attributes(descr))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let s = match &ast.data {
        syn::Data::Struct(ref s) => generate_ncp_packet(s, name.to_string()),
        _ => {
            let ts = syn::Error::new(ast.ident.span(), "#[NcpPacket] can only be used on structs");
            return ts.to_compile_error().into();
        }
    };
    match s {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
