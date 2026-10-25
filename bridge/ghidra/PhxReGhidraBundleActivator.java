import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

// Compile the no-op activator with PhxRE's scripts. Otherwise Ghidra generates
// one afterward and opens a second Java compiler and file manager.
public final class PhxReGhidraBundleActivator implements BundleActivator {
    @Override
    public void start(BundleContext context) {
    }

    @Override
    public void stop(BundleContext context) {
    }
}
