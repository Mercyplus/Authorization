from profile import Profile

from django.core.exceptions import ObjectDoesNotExist

from rest_framework import serializers
from rest_auth.registration.views import SocialLoginView
from rest_auth.registration.serializers import SocialLoginSerializer
from rest_framework.authtoken.admin import User
from rest_framework.exceptions import PermissionDenied

from authorization.helpers import valid_metamask_message, valid_totp
from authorization.serializers import init_profile


class MetamaskLoginSerializer(SocialLoginSerializer):
    address = serializers.CharField(required=False, allow_blank=True)
    msg = serializers.CharField(required=False, allow_blank=True)
    signed_msg = serializers.CharField(required=False, allow_blank=True)
    totp = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        address = attrs['address']
        signature = attrs['signed_msg']
        session = self.context['request'].session
        message = session.get('metamask_message')

        if message is None:
            message = attrs['msg']

        print('metamask login, address', address, 'message', message, 'signature', signature, flush=True)
        if valid_metamask_message(address, message, signature):
            metamask_user = User.objects.filter(username=address).first()
            if metamask_user is None:
                self.user = User.objects.create_user(username=address)
            else:
                self.user = metamask_user

            attrs['user'] = self.user
        else:
            raise PermissionDenied(1034)

        return attrs


class MetamaskLogin(SocialLoginView):
    serializer_class = MetamaskLoginSerializer

    def login(self):
        self.user = self.serializer.validated_data['user']
        metamask_address = self.serializer.validated_data['address']
        try:
            p = Profile.objects.get(user=self.user)
        except ObjectDoesNotExist:
            print('try create user', flush=True)
            init_profile(self.user, is_social=True, metamask_address=metamask_address,
                         lang=self.serializer.context['request'].COOKIES.get('lang', 'en'))
            self.user.save()
            print('user_created', flush=True)
        if self.user.profile.use_totp:
            totp = self.serializer.validated_data.get('totp', None)
            if not totp:
                # logout(self.request)
                raise PermissionDenied(1032)
            if not valid_totp(self.user, totp):
                # logout(self.request)
                raise PermissionDenied(1033)
        return super().login()