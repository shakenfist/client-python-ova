import click
from shakenfist_client import apiclient


def _emit_debug(ctx, m):
    if ctx.obj['VERBOSE']:
        print(m)


@click.group(help='OVA commands (via the shakenfist-client-ova plugin)')
def ova():
    ...


@ova.command(name='import', help='Import an OVA file')
@click.option('--namespace', type=click.STRING,
              help=('If you are an admin, you can import the OVA into a '
                    'different namespace.'))
@click.pass_context
def ova_import(ctx, namespace=None, ):
    print('...')


ova.add_command(ova_import)