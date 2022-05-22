use proc_macro::TokenStream;
use quote::quote;

use syn::{parse_macro_input, DeriveInput, Error};
use syn::spanned::Spanned;

enum Type {
    U8,
    U16,
    U32,
    MaxBoundedString,
    PathString,
}

struct Field {
    name: String,
    typ: Type,
}

struct NcpPacket {
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
        "PathString" => Some(Type::PathString),
        _ => { None }
    }
}

fn generate_read_for_type(ty: &Type, rdr: &str) -> String {
    match ty {
        Type::U8 => { format!("{rdr}.read_u8()?", rdr=rdr) },
        Type::U16 => { format!("{rdr}.read_u16::<BigEndian>()?", rdr=rdr) },
        Type::U32 => { format!("{rdr}.read_u32::<BigEndian>()?", rdr=rdr) },
        Type::MaxBoundedString => { format!("MaxBoundedString::from({rdr})?", rdr=rdr) },
        Type::PathString => { format!("PathString::from({rdr})?", rdr=rdr) },
    }
}

fn parse_packet(s: &syn::DataStruct) -> Result<NcpPacket, Error> {
    let mut fields: Vec<Field> = Vec::new();
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
        fields.push(Field{ name, typ })
    }
    Ok(NcpPacket{ fields })
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

fn generate_ncp_packet(s: &syn::DataStruct, name: String) -> Result<proc_macro2::TokenStream, Error> {
    let ncp_packet = parse_packet(s)?;

    let read_fields = generate_read_fields(&ncp_packet)?;
    let field_names = generate_field_names(&ncp_packet)?;

    let impls = format!("
        impl {name} {{
            pub fn from<T: Read + ReadBytesExt>(rdr: &mut T) -> Result<Self, NetWareError> {{
                {read_fields}
                Ok(Self{{ {field_names} }})
            }}
        }}
    ", name=name, read_fields=read_fields, field_names=field_names);
    let stmt: syn::Stmt = syn::parse_str(&impls).expect("generate_ncp_packet failed");
    let ts = quote! { #stmt };
    Ok(ts)
}

#[proc_macro_derive(NcpPacket)]
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
