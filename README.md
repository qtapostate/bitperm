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
A scope can encapsulate multiple permissions and operate on them as a group.

To add a permission to a scope:
```rust
  let mut scope = Scope::new("TEST_SCOPE");

  // now add a permission
  scope.add_permission("TEST_PERMISSION");
```
Notably here we do not have to specify a `shift` parameter because a `Scope` will manage that for us, incrementing
the underlying "next shift" each time a permission is successfully added to the scope.

To add multiple permissions to the scope:
```rust
  let mut scope = Scope::new("TEST_SCOPE");

  if let Ok(_) = scope
    .add_permission("READ")
    .and_then(|sc| sc.add_permission("WRITE"))
    .and_then(|sc| sc.add_permission("EXECUTE")) {
        // all succeeded, do something with the updated scope...
    }
```

### Adding Child Scopes to a Scope
We can add a child scope to a containing scope by using `.add_scope`

```rust
  let mut scope = Scope::new("TEST_SCOPE");

  if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
    if let Some(child_scope) = scope.scope("CHILD_SCOPE") {
        // do something with the child scope
    }
  } else {
    // failed to create the child scope
  }

```

### Adding Permissions to a Child Scope
We can add permissions to a child scope the same way we would add them to a containing scope.
Presently, a child scope must first be attached before permissions are added to it.

When we have a child scope, we can also add permissions to that child scope.
This might represent a more granular level of permissivity as opposed to the resource represented by a
containing scope. It also allows us to break up our permissions and effectively circumvent the limitation of
52 permissions per scope.

```rust
  let mut scope = Scope::new("TEST_SCOPE");

  if let Ok(_) = scope.add_scope("CHILD_SCOPE") {
    if let Some(child_scope) = scope.scope("CHILD_SCOPE") {
        if let Ok(_) = child_scope.add_permission("TEST_CHILD_PERMISSION") {
            // added the permission successfully, do something else...
        }
    }
  } else {
    // failed to create the child scope
  }

```

### Converting to a Number or Tuple
An easier way to deal with permissions can be to treat them as numbers.
While a scope has more functionality when in its fully representative form, a "permission number" can be
useful for performing bitwise operations but especially for transferring over the wire. This is a core design
philosophy - that it is more efficient to transfer extensive permission profiles in this format as opposed to
extensive JSON format. It may also be more effective to store them in this format and inflate them to their
full form at runtime when needed.

```rust
    let mut scope = Scope::new("TEST_SCOPE");

    if let Ok(_) = scope
        .add_permission("READ")
        .and_then(|sc| sc.add_permission("WRITE"))
        .and_then(|sc| sc.add_permission("EXECUTE")) {

        // grant all of the permissions
        for perm in vec!["READ", "WRITE", "EXECUTE"] {
            scope.permission(perm).and_then(|p| {
                return if let Ok(granted) = p.grant() {
                    Some(granted)
                } else {
                    None
                }
            });
        }

        let permissions_numeric = scope.as_u64(); // in this example the u64 value is 7 and always takes 8 bytes

        // do something with the value...

    } else {
        // failed to add the permissions...
    }

```

### Exporting to JSON, YAML, or PKL format

WIP

### Importing from JSON, YAML, or PKL format

WIP
