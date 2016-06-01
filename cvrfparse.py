#!/usr/bin/env python
"""Parse/Validate a CVRF file and emit user-specified fields. Requires lxml.
"""

__author__ = "Mike Schiffman"
__email__ = "mschiffm@cisco.com"
__credits__ = "William McVey"
__date__ = "November 2013"
__revision__ = "1.0"
__maintainer__ = "Mike Schiffman"

import os
import sys
import copy
import codecs
import urllib2
import argparse
import logging
from lxml import etree


class CVRF_Syntax(object):
    """
    All of the CVRF Elements and Namespaces are kept here.  As CVRF evolves, make appropriate changes here.
    """
    NAMESPACES = {x.upper(): "{http://www.icasi.org/CVRF/schema/%s/1.1}" % x for x in ("cvrf", "vuln", "prod")}
    CVRF_ARGS = ["all", "DocumentTitle", "DocumentType", "DocumentPublisher", "DocumentTracking", "DocumentNotes",
                 "DocumentDistribution", "AggregateSeverity", "DocumentReferences", "Acknowledgments"]
    VULN_ARGS = ["all", "Title", "ID", "Notes", "DiscoveryDate", "ReleaseDate", "Involvements", "CVE", "CWE",
                 "ProductStatuses", "Threats", "CVSSScoreSets", "Remediations", "References", "Acknowledgments"]
    PROD_ARGS = ["all", "Branch", "FullProductName", "Relationship", "ProductGroups"]
    CVRF_SCHEMA = "http://www.icasi.org/CVRF/schema/cvrf/1.1/cvrf.xsd"
    CVRF_CATALOG = "./cvrfparse/schemata/catalog.xml"

def chop_ns_prefix(element):
    """
    Return the element of a fully qualified namespace URI

    element: a fully qualified ET element tag
    """
    return element[element.rindex("}") + 1:]

def _create_parsables(elements):
    '''Create formatted parsable list with user entered elements'''
    parsables = []
    for element in elements:
        if element in CVRF_Syntax.CVRF_ARGS:
            args_cvrf = [CVRF_Syntax.NAMESPACES['CVRF'] + element]
            parsables.extend(post_process_arglist(args_cvrf, 'CVRF', CVRF_Syntax.CVRF_ARGS))
        if element in CVRF_Syntax.VULN_ARGS:
            args_vuln = [CVRF_Syntax.NAMESPACES['VULN'] + element]
            parsables.extend(post_process_arglist(args_vuln, 'CVRF', CVRF_Syntax.CVRF_ARGS))
        if element in CVRF_Syntax.PROD_ARGS:
            args_prod = [CVRF_Syntax.NAMESPACES['PROD'] + element]
            parsables.extend(post_process_arglist(args_prod, 'PROD', CVRF_Syntax.CVRF_ARGS))
    return parsables


def print_node(node, strip_ns, f=sys.stdout):
    """
    Print each XML node

    node: the ElementTree node to be printed
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    f: the file to print to (default is stdout)
    """
    if node.tag:
        print >> f, "[%s]" %(chop_ns_prefix(node.tag) if strip_ns else node.tag),
    if node.text:
        print >> f, node.text.strip()
    if node.attrib:
        for key in node.attrib:
            print >> f, "(%s: %s)" %(key, node.attrib[key])
        print >> f


def cvrf_validate(f, cvrf_doc):
    """
    Validates a CVRF document

    f: file object containing the schema
    cvrf_doc: the serialized CVRF ElementTree object
    returns: a code (True for valid / False for invalid) and a reason for the code
    """
    try:
        xmlschema_doc = etree.parse(f)
    except etree.XMLSyntaxError as e:
        log = e.error_log.filter_from_level(etree.ErrorLevels.FATAL)
        return False, "Parsing error, schema document \"{0}\" is not well-formed: {1}".format(f.name, log)
    xmlschema = etree.XMLSchema(xmlschema_doc)

    try:
        xmlschema.assertValid(cvrf_doc)
        return True, "Valid"
    except etree.DocumentInvalid:
        return False, xmlschema.error_log


def cvrf_dump(results, strip_ns):
    """
    Iterates over results and dumps to the dictionary key (which is a file handle)

    results: a dictionary of the format: {filename, [ElementTree node, ...], ...}
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    """
    for key in results:
        if key == "stdout":
            f = codecs.EncodedFile(sys.stdout, "UTF-8")
        else:
            try:
                f = codecs.open(key, "w", encoding="UTF-8")
            except IOError as e:
                sys.exit("{0}: I/O error({1}) \"{2}\": {3}".format(progname, e.errno, key, e.strerror))
        for item in results[key]:
            print_node(item, strip_ns, f)
        f.close()

def cvrf_dispatch(cvrf_doc, parsables, collate_vuln, strip_ns):
    """
    Filter through a CVRF document and perform user-specified actions and report the results

    cvrf_doc: the serialized CVRF ElementTree object
    collate_vuln: boolean indicating whether or not to collate the vulnerabilities
    strip_ns: boolean that when true indicates the namespace prefix will be chomped
    returns: N/A

    """
    if parsables:
        results = cvrf_parse(cvrf_doc, parsables)
        cvrf_dump(results, strip_ns)
    if collate_vuln:
        results = cvrf_collate_vuln(cvrf_doc)
        cvrf_dump(results, strip_ns)


def cvrf_parse(cvrf_doc, parsables):
    """
    Parse a cvrf_doc and return a list of elements as determined by parsables

    cvrf_doc: the serialized CVRF ElementTree object
    parsables: list of elements to parse from a CVRF doc
    returns: a dictionary of the format {filename:[item, ...]}
    """

    items = []
    elem_dict = {}
    for element in parsables:
        for node in cvrf_doc.iter(element):
            for child in node.iter():
                elem_dict[chop_ns_prefix(child.tag)] = child.text
                items.append(child)
    return elem_dict

def parse(file_name, elements):
    cvrf_doc = etree.parse(file_name, etree.XMLParser(encoding="UTF-8"))
    parsables = _create_parsables(elements)
    return cvrf_parse(cvrf_doc, parsables)

def cvrf_collate_vuln(cvrf_doc):
    """
    Zip through a cvrf_doc and return all vulnerability elements collated by ordinal

    cvrf_doc: the serialized CVRF ElementTree object
    returns: a dictionary of the format {filename:[item, ...], filename:[item, ...]}
    """
    results = {}
    # Obtain document title to use in the filename(s) tiptoeing around around the curly braces in our NS definition
    document_title = cvrf_doc.findtext("cvrf:DocumentTitle",
                                       namespaces={"cvrf": CVRF_Syntax.NAMESPACES["CVRF"].replace("{", "").replace("}", "")}).strip().replace(" ", "_")

    # Constrain Xpath search to the Vulnerability container
    for node in cvrf_doc.findall(".//" + CVRF_Syntax.NAMESPACES["VULN"] + "Vulnerability"):
        # Create filename based on ordinal number to use as a key for results dictionary
        filename = "cvrfparse-" + document_title + "-ordinal-" + node.attrib["Ordinal"] + ".txt"
        # Create an iterator to iterate over each child element and populate results dictionary values
        results[filename] = node.iter()

    return results


def post_process_arglist(arg, namespace, valid_args):
    parsables = []
    if CVRF_Syntax.NAMESPACES[namespace] + "all" in arg:
        for element in valid_args:
            parsables.append(CVRF_Syntax.NAMESPACES[namespace] + element)
        parsables.remove(CVRF_Syntax.NAMESPACES[namespace] + "all")
    else:
        for element in arg:
            parsables.append(element)
    return parsables

if __name__ == "__main__":
    results = parse('sample-xml/cvrf.xml', ['DocumentTitle', 'DocumentType', 'ID'])
    print results
