# bitperm
Permissions evaluation library designed to reduce the footprint of JWT permission evaluation.

## Key Features
* Exposes a rudimentary API for working with bitwise permissions,
divided into individual permissions and groups of permissions.
* Designed to keep token size predictable and minimal when encoding permissions on a JSON Web Token (JWT).
  * Up to 52 permission rules can be encoded into a single unsigned 64-bit integer (u64).
  * An "infinite" number of scopes can be added to break up permissions further, allowing for hundreds of permissions.

### WIP Features
* **WIP:** Programmatic and CLI support for exporting to and importing from JSON, YAML, or PKL format.
* **WIP:** Native support for Node 18+.

### Planned/Future Features
* **Planned:** Support for the following Rust HTTP frameworks: Rocket vTBD+, Warp vTBD+, Poem vTBD+
* **Planned:** Support for the following NodeJS HTTP frameworks: Express vTBD+
* **Planned:** Native support for Python 3.

## Brief Overview
Full development documentation forthcoming. For now, this is a basic guide to using this utility.
A `Permission` is the basic building block of bitperm, holding logic for granting and revoking permissions within a scope.
A `Scope` is a grouping of up to 52 `Permission`s and can also be linked to other child scopes to store more.

### Create a Permission
To create a new permission, use the static function `::new`.
```rust

    let new_permission = Permission::new("MY_PERMISSION", 5); // returns a Result<Permission, ErrorKind>

```

This will create a new permission `"MY_PERMISSION"` with an individual value of `32`, which is equal to `1 << 5`.
When we call this function, a few preflight checks are performed to ensure the left-shift would be safe for
conversion back into JS. Backward compatibility for JS imposes an upper limit that is lower than the typical
64 bits that would ordinarily be available in an unsigned 64-bit integer.

### Grant and Revoke Permissions
Once we have a `Permission` we can use `.grant()` and `.revoke()` to mark whether the user has it.

**Granting a permission...**
```rust
    // something like this...
    let granted = Permission::new("MY_PERMISSION", 5)
      .and_then(|mut permission| {
        return match permission.grant() {
            Ok(_) => Ok(permission),
            Err(err) => Err(err)
        }
      });

```
Granting the permission will cause it to be counted when it is evaluated. If it is granted, its value will be included
in the final "permission number", otherwise it will be excluded. Furthermore, granting a permission that is already
granted will cause an error to be returned in the result of `.grant()`. **The default state for every permission is revoked.**

**Revoking a permission...**
```rust
    // something like this...
    let revoked = Permission::new("MY_PERMISSION", 5) // created, now let's grant the permission
      .and_then(|mut permission| {
        return match permission.grant() {
          Ok(_) => Ok(permission),
          Err(err) => Err(err)
        }
      }) // permission is now granted
      .and_then(|mut permission| { // now let's revoke the permission
        return match permission.revoke() {
          Ok(_) => Ok(permission),
          Err(err) => Err(err)
        }
      }); // permission is now revoked

```
Revoking the permission will cause it to be counted when it is evaluated. If it is revoked, its value will **not** included
in the final "permission number". Furthermore, granting a permission that is already
granted will cause an error to be returned in the result of `.revoke()`.

### Adding Permissions to a Scope

TODO

### Adding Child Scopes to a Scope

TODO

### Converting to a Number or Tuple

TODO

### Exporting to JSON, YAML, or PKL format

TODO

### Importing from JSON, YAML, or PKL format

TODO
