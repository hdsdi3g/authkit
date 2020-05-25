# AuthKit usage in an external project

After read README.md, INSTALL.md, SECURITY.md, let's use AuthKit in a project.

Create a class with annotations like:

```java
@Configuration
@ComponentScan(
        basePackages = { "tv.hd3g.authkit.mod" })
@EnableJpaRepositories("tv.hd3g.authkit.mod.repository")
@EntityScan("tv.hd3g.authkit.mod.entity")
public class Setup {
    /* Other configuration declarations */
}
```

## Right checks

And add on Controller some annotations:

```java
@Controller
@CheckBefore("secureOnClass")
public class ControllerWithSecure {

    @CheckBefore("secureOnMethod")
    public void verbWithSecure() {
    }

    public void verbWithoutSecure() {
    }
}
```

An user must have rights for:

- `secureOnClass` and `secureOnMethod` for call `verbWithSecure()`
- just `secureOnClass` for call `verbWithoutSecure()`

## Audit after call controller

Go to `src/test/java/tv/hd3g/authkit/dummy/ControllerAudit.java` to see an example.

All `@AuditAfter` annotations will add a database entry and a log entry after each call, and some request informations (like IP, user UUID...) will be stored.
