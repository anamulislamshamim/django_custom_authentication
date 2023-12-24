# create logout mixin so that we can protect login user from to visit 
# login page.
from django.shortcuts import redirect
 
class LogoutRequiredMixin(object):
    def dispatch(self, *args, **kwargs):
        if self.request.user.is_authenticated:
            return redirect('home')
        return super(LogoutRequiredMixin, self).dispatch(*args, **kwargs)