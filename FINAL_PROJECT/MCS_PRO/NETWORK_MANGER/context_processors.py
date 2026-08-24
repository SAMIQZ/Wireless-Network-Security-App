def user_theme(request):

    css = ''
    try:
        if request.user.is_authenticated:
            from .views import get_user_theme_css
            css = get_user_theme_css(request.user)
    except Exception:
        pass
    return {'theme_css': css}
