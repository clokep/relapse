# Copyright 2022 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import TYPE_CHECKING, Optional

from pydantic import ConfigDict, StringConstraints, field_validator, model_validator
from typing_extensions import Annotated, Self

from relapse.rest.models import RequestBodyModel
from relapse.util.threepids import validate_email


class AuthenticationData(RequestBodyModel):
    """
    Data used during user-interactive authentication.

    (The name "Authentication Data" is taken directly from the spec.)

    Additional keys will be present, depending on the `type` field. Use
    `.dict(exclude_unset=True)` to access them.
    """

    model_config = ConfigDict(extra="allow", strict=True)

    session: Optional[str] = None
    type: Optional[str] = None


if TYPE_CHECKING:
    ClientSecretStr = str
else:
    # See also assert_valid_client_secret()
    ClientSecretStr = Annotated[
        str,
        StringConstraints(
            pattern="[0-9a-zA-Z.=_-]",  # noqa: F722
            min_length=1,
            max_length=255,
            strict=True,
        ),
    ]


class ThreepidRequestTokenBody(RequestBodyModel):
    client_secret: ClientSecretStr
    id_server: Optional[str] = None
    id_access_token: Optional[str] = None
    next_link: Optional[str] = None
    send_attempt: int

    @model_validator(mode="after")
    def token_required_for_identity_server(self) -> Self:
        if self.id_server is not None and self.id_access_token is None:
            raise ValueError("id_access_token is required if an id_server is supplied.")
        return self


class EmailRequestTokenBody(ThreepidRequestTokenBody):
    email: str

    # Canonicalise the email address. The addresses are all stored canonicalised
    # in the database. This allows the user to reset his password without having to
    # know the exact spelling (eg. upper and lower case) of address in the database.
    # Without this, an email stored in the database as "foo@bar.com" would cause
    # user requests for "FOO@bar.com" to raise a Not Found error.
    _email_validator = field_validator("email")(validate_email)


if TYPE_CHECKING:
    ISO3116_1_Alpha_2 = str
else:
    # Per spec: two-letter uppercase ISO-3166-1-alpha-2
    ISO3116_1_Alpha_2 = Annotated[
        str, StringConstraints(pattern="[A-Z]{2}", strict=True)
    ]


class MsisdnRequestTokenBody(ThreepidRequestTokenBody):
    country: ISO3116_1_Alpha_2
    phone_number: str
